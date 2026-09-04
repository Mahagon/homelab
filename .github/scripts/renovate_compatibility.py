#!/usr/bin/env python3
"""Render and validate dependency changes made by Renovate."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable, Sequence

import yaml


PLACEHOLDERS = {
    "${DOMAIN}": "example.invalid",
    "${EMAIL}": "security@example.com",
}
ADDED_IMAGE = re.compile(r"^\+(?!\+\+).*?\bimage:\s*[\"']?([^\s\"'#]+)")
CommandRunner = Callable[[Sequence[str]], str]


@dataclass(frozen=True)
class HelmSource:
    application: str
    namespace: str
    repository: str
    chart: str
    version: str
    values: str


def run(command: Sequence[str]) -> str:
    """Run a command and return stdout, failing with the command's diagnostics."""
    result = subprocess.run(
        list(command),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if result.stderr:
        print(result.stderr, file=sys.stderr, end="")
    if result.returncode != 0 and result.stdout:
        print(result.stdout, file=sys.stderr, end="")
    result.check_returncode()
    return result.stdout


def substitute_placeholders(value: str) -> str:
    for placeholder, replacement in PLACEHOLDERS.items():
        value = value.replace(placeholder, replacement)
    return value


def helm_sources(document: dict[str, Any]) -> list[HelmSource]:
    if document.get("kind") != "Application":
        return []

    metadata = document.get("metadata") or {}
    spec = document.get("spec") or {}
    destination = spec.get("destination") or {}
    candidates: list[dict[str, Any]] = []
    if isinstance(spec.get("source"), dict):
        candidates.append(spec["source"])
    if isinstance(spec.get("sources"), list):
        candidates.extend(source for source in spec["sources"] if isinstance(source, dict))

    result: list[HelmSource] = []
    for source in candidates:
        if "chart" not in source:
            continue
        required = ("repoURL", "chart", "targetRevision")
        missing = [key for key in required if not source.get(key)]
        if missing:
            raise ValueError(f"Helm source is missing: {', '.join(missing)}")
        helm = source.get("helm") or {}
        if helm.get("valueFiles"):
            raise ValueError("Helm valueFiles are not supported by the compatibility renderer")
        result.append(
            HelmSource(
                application=str(metadata.get("name") or "application"),
                namespace=str(destination.get("namespace") or "default"),
                repository=str(source["repoURL"]),
                chart=str(source["chart"]),
                version=str(source["targetRevision"]),
                values=str(helm.get("values") or ""),
            )
        )
    return result


def load_helm_sources(path: Path) -> list[HelmSource]:
    sources: list[HelmSource] = []
    for document in yaml.safe_load_all(path.read_text(encoding="utf-8")):
        if isinstance(document, dict):
            sources.extend(helm_sources(document))
    return sources


def added_image_references(diff: str) -> list[str]:
    references = {
        match.group(1)
        for line in diff.splitlines()
        if (match := ADDED_IMAGE.match(line)) is not None
    }
    return sorted(references)


def supports_platform(descriptor: dict[str, Any], os_name: str, architecture: str) -> bool:
    manifests = descriptor.get("manifests")
    if isinstance(manifests, list):
        return any(
            manifest.get("platform", {}).get("os") == os_name
            and manifest.get("platform", {}).get("architecture") == architecture
            for manifest in manifests
            if isinstance(manifest, dict)
        )
    platform = descriptor.get("platform") or {}
    return platform.get("os") == os_name and platform.get("architecture") == architecture


def inspect_descriptor(reference: str, runner: CommandRunner = run) -> dict[str, Any]:
    output = runner(
        [
            "docker",
            "buildx",
            "imagetools",
            "inspect",
            reference,
            "--format",
            "{{json .Manifest}}",
        ]
    )
    descriptor = json.loads(output)
    if not isinstance(descriptor, dict):
        raise ValueError(f"Image inspection returned an invalid descriptor for {reference}")
    return descriptor


def validate_image(reference: str, runner: CommandRunner = run) -> None:
    descriptor = inspect_descriptor(reference, runner)
    if not supports_platform(descriptor, "linux", "amd64"):
        raise ValueError(f"{reference} does not provide a linux/amd64 image")

    tagged_reference, separator, pinned_digest = reference.partition("@")
    if not separator:
        return
    actual_digest = descriptor.get("digest")
    if actual_digest != pinned_digest:
        raise ValueError(
            f"{reference} resolved to {actual_digest!r}, not its pinned digest {pinned_digest!r}"
        )

    final_component = tagged_reference.rsplit("/", 1)[-1]
    if ":" not in final_component:
        return
    tag_descriptor = inspect_descriptor(tagged_reference, runner)
    if tag_descriptor.get("digest") != pinned_digest:
        raise ValueError(
            f"Tag {tagged_reference} resolves to {tag_descriptor.get('digest')!r}, "
            f"not the pinned digest {pinned_digest!r}"
        )


def changed_files(base: str, head: str, runner: CommandRunner = run) -> list[Path]:
    output = runner(["git", "diff", "--name-only", "--diff-filter=ACMR", base, head])
    return [Path(line) for line in output.splitlines() if line]


def render_raw_manifests(paths: Iterable[Path], output: Path) -> int:
    output.mkdir(parents=True, exist_ok=True)
    count = 0
    for path in paths:
        parts = path.as_posix().split("/")
        if len(parts) < 5 or parts[:2] != ["k8s", "apps"] or "manifests" not in parts:
            continue
        if path.suffix not in {".yaml", ".yml"}:
            continue
        rendered = substitute_placeholders(path.read_text(encoding="utf-8"))
        target = output / f"raw-{parts[2]}-{path.name}"
        target.write_text(rendered, encoding="utf-8")
        count += 1
    return count


def safe_name(value: str) -> str:
    return re.sub(r"[^a-z0-9-]+", "-", value.lower()).strip("-")[:53] or "application"


def render_helm_sources(
    application_paths: Iterable[Path],
    output: Path,
    kubernetes_version: str,
    runner: CommandRunner = run,
) -> int:
    output.mkdir(parents=True, exist_ok=True)
    count = 0
    for path in application_paths:
        if not path.as_posix().startswith("k8s/apps/") or path.name != "application.yaml":
            continue
        for index, source in enumerate(load_helm_sources(path), start=1):
            release = safe_name(f"{source.application}-{source.chart}")
            values_path = output / f"{release}-{index}-values.yaml"
            values_path.write_text(substitute_placeholders(source.values), encoding="utf-8")
            command = [
                "helm",
                "template",
                release,
                source.chart,
                "--repo",
                source.repository,
                "--version",
                source.version,
                "--namespace",
                source.namespace,
                "--kube-version",
                kubernetes_version,
                "--include-crds",
            ]
            if source.values:
                command.extend(["--values", str(values_path)])
            rendered = runner(command)
            (output / f"helm-{release}-{index}.yaml").write_text(rendered, encoding="utf-8")
            values_path.unlink(missing_ok=True)
            count += 1
    return count


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", required=True)
    parser.add_argument("--head", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--kubernetes-version", required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    paths = changed_files(args.base, args.head)
    raw_count = render_raw_manifests(paths, args.output)
    helm_count = render_helm_sources(paths, args.output, args.kubernetes_version)

    diff = run(["git", "diff", "--unified=0", args.base, args.head, "--", "*.yaml", "*.yml"])
    images = added_image_references(diff)
    for image in images:
        print(f"Inspecting {image}")
        validate_image(image)

    print(
        f"Compatibility inputs: {helm_count} Helm chart(s), "
        f"{raw_count} raw manifest(s), {len(images)} image(s)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
