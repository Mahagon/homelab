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
from typing import Callable, Iterable, Sequence, cast

import yaml

PLACEHOLDERS = {
    "${DOMAIN}": "example.invalid",
    "${EMAIL}": "security@example.com",
}
ADDED_IMAGE = re.compile(r"^\+(?!\+\+).*?\bimage:\s*[\"']?([^\s\"'#]+)")
CommandRunner = Callable[[Sequence[str]], str]
YamlMap = dict[str, object]


def as_mapping(value: object) -> YamlMap:
    """Return a string-keyed mapping or an empty mapping."""
    if not isinstance(value, dict):
        return {}
    mapping = cast(dict[object, object], value)
    return {key: item for key, item in mapping.items() if isinstance(key, str)}


def as_list(value: object) -> list[object]:
    """Return a sequence as explicitly object-typed values."""
    if not isinstance(value, list):
        return []
    return cast(list[object], value)


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
    """Replace known deployment placeholders with schema-safe test values."""
    for placeholder, replacement in PLACEHOLDERS.items():
        value = value.replace(placeholder, replacement)
    return value


def helm_sources(document: object) -> list[HelmSource]:
    """Extract renderable Helm sources from an Argo CD Application."""
    document = as_mapping(document)
    if document.get("kind") != "Application":
        return []

    metadata = as_mapping(document.get("metadata"))
    spec = as_mapping(document.get("spec"))
    destination = as_mapping(spec.get("destination"))
    candidates: list[YamlMap] = []
    source = as_mapping(spec.get("source"))
    if source:
        candidates.append(source)
    candidates.extend(
        candidate
        for value in as_list(spec.get("sources"))
        if (candidate := as_mapping(value))
    )

    result: list[HelmSource] = []
    for source in candidates:
        if "chart" not in source:
            continue
        required = ("repoURL", "chart", "targetRevision")
        missing = [key for key in required if not source.get(key)]
        if missing:
            raise ValueError(f"Helm source is missing: {', '.join(missing)}")
        helm = as_mapping(source.get("helm"))
        if helm.get("valueFiles"):
            raise ValueError(
                "Helm valueFiles are not supported by the compatibility renderer"
            )
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
    """Load every renderable Helm source declared in a YAML file."""
    sources: list[HelmSource] = []
    documents = cast(
        Iterable[object], yaml.safe_load_all(path.read_text(encoding="utf-8"))
    )
    for document in documents:
        sources.extend(helm_sources(document))
    return sources


def added_image_references(diff: str) -> list[str]:
    """Return unique image references added by a unified diff."""
    references = {
        match.group(1)
        for line in diff.splitlines()
        if (match := ADDED_IMAGE.match(line)) is not None
    }
    return sorted(references)


def supports_platform(
    descriptor: YamlMap, os_name: str, architecture: str
) -> bool:
    """Return whether an image descriptor supports the requested platform."""
    manifests_value = descriptor.get("manifests")
    if isinstance(manifests_value, list):
        manifests = cast(list[object], manifests_value)
        return any(
            platform.get("os") == os_name
            and platform.get("architecture") == architecture
            for value in manifests
            if (manifest := as_mapping(value))
            if (platform := as_mapping(manifest.get("platform")))
        )
    platform = as_mapping(descriptor.get("platform")) or descriptor
    return (
        platform.get("os") == os_name and platform.get("architecture") == architecture
    )


def inspect_descriptor(reference: str, runner: CommandRunner = run) -> YamlMap:
    """Inspect and decode an image manifest descriptor."""
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
    decoded = cast(object, json.loads(output))
    if not isinstance(decoded, dict):
        raise ValueError(
            f"Image inspection returned an invalid descriptor for {reference}"
        )
    return as_mapping(cast(object, decoded))


def inspect_image_config(reference: str, runner: CommandRunner = run) -> YamlMap:
    """Return config metadata used to identify a single-platform manifest."""
    output = runner(
        [
            "docker",
            "buildx",
            "imagetools",
            "inspect",
            reference,
            "--format",
            "{{json .Image}}",
        ]
    )
    decoded = cast(object, json.loads(output))
    if not isinstance(decoded, dict):
        raise ValueError(f"Image inspection returned invalid config for {reference}")
    return as_mapping(cast(object, decoded))


def validate_image(
    reference: str,
    runner: CommandRunner = run,
    *,
    require_tag_match: bool = True,
) -> None:
    """Validate image availability, platform support, digest, and optional tag."""
    descriptor = inspect_descriptor(reference, runner)
    platform_descriptor = descriptor
    if not isinstance(descriptor.get("manifests"), list):
        platform_descriptor = inspect_image_config(reference, runner)
    if not supports_platform(platform_descriptor, "linux", "amd64"):
        raise ValueError(
            f"{reference} does not provide a linux/amd64 image; "
            f"reported platform metadata: {platform_descriptor!r}"
        )

    tagged_reference, separator, pinned_digest = reference.partition("@")
    if not separator:
        return
    actual_digest = descriptor.get("digest")
    if actual_digest != pinned_digest:
        raise ValueError(
            f"{reference} resolved to {actual_digest!r}, not its pinned digest {pinned_digest!r}"
        )

    final_component = tagged_reference.rsplit("/", 1)[-1]
    if not require_tag_match or ":" not in final_component:
        return
    tag_descriptor = inspect_descriptor(tagged_reference, runner)
    if tag_descriptor.get("digest") != pinned_digest:
        raise ValueError(
            f"Tag {tagged_reference} resolves to {tag_descriptor.get('digest')!r}, "
            f"not the pinned digest {pinned_digest!r}"
        )


def changed_files(base: str, head: str, runner: CommandRunner = run) -> list[Path]:
    """Return added, copied, modified, or renamed files between revisions."""
    output = runner(["git", "diff", "--name-only", "--diff-filter=ACMR", base, head])
    return [Path(line) for line in output.splitlines() if line]


def render_raw_manifests(paths: Iterable[Path], output: Path) -> int:
    """Render changed raw manifests with safe placeholder substitutions."""
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
    """Convert a value into a bounded Kubernetes-compatible name fragment."""
    return re.sub(r"[^a-z0-9-]+", "-", value.lower()).strip("-")[:53] or "application"


def render_helm_sources(
    application_paths: Iterable[Path],
    output: Path,
    kubernetes_version: str,
    runner: CommandRunner = run,
) -> int:
    """Render Helm sources referenced by the provided Application paths."""
    output.mkdir(parents=True, exist_ok=True)
    count = 0
    for path in application_paths:
        if (
            not path.as_posix().startswith("k8s/apps/")
            or path.name != "application.yaml"
        ):
            continue
        for index, source in enumerate(load_helm_sources(path), start=1):
            release = safe_name(f"{source.application}-{source.chart}")
            values_path = output / f"{release}-{index}-values.yaml"
            values_path.write_text(
                substitute_placeholders(source.values), encoding="utf-8"
            )
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
            (output / f"helm-{release}-{index}.yaml").write_text(
                rendered, encoding="utf-8"
            )
            values_path.unlink(missing_ok=True)
            count += 1
    return count


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", required=True)
    parser.add_argument("--head", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--kubernetes-version", required=True)
    return parser.parse_args()


def main() -> int:
    """Validate Renovate changes for rendering and image compatibility."""
    args = parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    paths = changed_files(args.base, args.head)
    raw_count = render_raw_manifests(paths, args.output)
    helm_count = render_helm_sources(paths, args.output, args.kubernetes_version)

    diff = run(
        ["git", "diff", "--unified=0", args.base, args.head, "--", "*.yaml", "*.yml"]
    )
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
