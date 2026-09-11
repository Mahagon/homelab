#!/usr/bin/env python3
"""Inventory deployed Kubernetes images from raw manifests and Helm charts."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path
from typing import Any, Iterable, cast

from renovate_compatibility import (
    HelmSource,
    added_image_references,
    changed_files,
    helm_sources,
    render_raw_manifests,
    run,
    safe_name,
    substitute_placeholders,
    validate_image,
)


IMAGE_REFERENCE = re.compile(r"(?m)^[ \t]*(?:-\s*)?image:\s*[\"']?([^\s\"'#]+)")
PINNED_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
DEFAULT_IGNORE = ".github/security/trivy/default.ignore"
IMAGE_IGNORE_FILES = {
    "cloudflare/cloudflared": ".github/security/trivy/cloudflared.ignore",
    "ghcr.io/renovatebot/renovate": ".github/security/trivy/renovate.ignore",
    "quay.io/argoproj/argocd": ".github/security/trivy/argocd.ignore",
}
YamlMap = dict[str, object]


def as_mapping(value: object) -> YamlMap:
    """Return a string-keyed YAML mapping or an empty mapping."""
    if not isinstance(value, dict):
        return {}
    return cast(YamlMap, value)


def as_list(value: object) -> list[object]:
    """Return a YAML sequence or an empty sequence."""
    if not isinstance(value, list):
        return []
    return cast(list[object], value)


def image_references(text: str) -> set[str]:
    """Return concrete image references declared in YAML or rendered YAML text."""
    return {
        match.group(1)
        for match in IMAGE_REFERENCE.finditer(text)
        if not any(token in match.group(1) for token in ("{{", "}}", "${"))
    }


def workload_image_references(text: str) -> set[str]:
    """Return images from rendered workload pods, excluding Helm test hooks."""
    import yaml

    references: set[str] = set()
    loaded_documents = cast(Iterable[object], yaml.safe_load_all(text))
    for loaded_document in loaded_documents:
        document = as_mapping(loaded_document)
        if not document:
            continue
        metadata = as_mapping(document.get("metadata"))
        annotations = as_mapping(metadata.get("annotations"))
        hook = annotations.get("helm.sh/hook")
        if "test" in str(hook or "").split(","):
            continue
        kind = document.get("kind")
        spec = as_mapping(document.get("spec"))
        if kind == "Pod":
            pod_spec = spec
        elif kind == "CronJob":
            job_template = as_mapping(spec.get("jobTemplate"))
            job_spec = as_mapping(job_template.get("spec"))
            template = as_mapping(job_spec.get("template"))
            pod_spec = as_mapping(template.get("spec"))
        elif kind in {
            "DaemonSet",
            "Deployment",
            "Job",
            "ReplicaSet",
            "ReplicationController",
            "StatefulSet",
        }:
            template = as_mapping(spec.get("template"))
            pod_spec = as_mapping(template.get("spec"))
        else:
            continue
        for container_type in ("initContainers", "containers", "ephemeralContainers"):
            for value in as_list(pod_spec.get(container_type)):
                container = as_mapping(value)
                image = container.get("image")
                if isinstance(image, str) and image:
                    references.add(image)
    return references


def explicit_image_references(paths: Iterable[Path]) -> set[str]:
    """Collect image references explicitly declared in repository YAML files."""
    references: set[str] = set()
    for path in paths:
        if path.suffix not in {".yaml", ".yml"} or not path.is_file():
            continue
        references.update(image_references(path.read_text(encoding="utf-8")))
    return references


def validate_explicit_pin(reference: str) -> None:
    """Require a readable tag and immutable sha256 digest for repository-owned refs."""
    tagged, separator, digest = reference.partition("@")
    if not separator or not PINNED_DIGEST.fullmatch(digest):
        raise ValueError(f"Explicit image is not pinned by sha256 digest: {reference}")
    final_component = tagged.rsplit("/", 1)[-1]
    if ":" not in final_component:
        raise ValueError(f"Explicit image does not include a human-readable tag: {reference}")


def canonical_image(reference: str) -> str:
    """Return an image repository without its tag or digest."""
    tagged = reference.partition("@")[0]
    prefix, separator, final = tagged.rpartition("/")
    repository = final.rsplit(":", 1)[0]
    return f"{prefix}{separator}{repository}" if separator else repository


def scan_category(reference: str) -> str:
    """Build a stable GitHub Code Scanning category for an image repository."""
    canonical = canonical_image(reference)
    digest = hashlib.sha256(canonical.encode()).hexdigest()[:8]
    return f"{safe_name(canonical)}-{digest}"


def ignore_file(reference: str) -> str:
    """Return the vulnerability allowlist scoped to an image repository."""
    return IMAGE_IGNORE_FILES.get(canonical_image(reference), DEFAULT_IGNORE)


def matrix_entries(
    raw_images: set[str], helm_images: set[str]
) -> list[dict[str, str]]:
    """Build deduplicated GitHub Actions matrix entries for image scans."""
    combined_sources: dict[str, set[str]] = {}
    for source, references in (("raw", raw_images), ("helm", helm_images)):
        for reference in references:
            tagged = reference.partition("@")[0]
            combined_sources.setdefault(tagged, set()).add(source)

    selected: dict[str, str] = {}
    for reference in sorted(raw_images | helm_images):
        tagged = reference.partition("@")[0]
        if tagged not in selected or "@" in reference:
            selected[tagged] = reference

    entries: list[dict[str, str]] = []
    canonical_counts: dict[str, int] = {}
    for reference in selected.values():
        canonical = canonical_image(reference)
        canonical_counts[canonical] = canonical_counts.get(canonical, 0) + 1

    for tagged, reference in sorted(selected.items(), key=lambda item: item[1]):
        sources = sorted(combined_sources[tagged], key=("raw", "helm").index)
        category = scan_category(reference)
        if canonical_counts[canonical_image(reference)] > 1:
            suffix = hashlib.sha256(tagged.encode()).hexdigest()[:8]
            category = f"{category}-{suffix}"
        entries.append(
            {
                "image": reference,
                "source": "+".join(sources),
                "ignorefile": ignore_file(reference),
                "category": category,
            }
        )
    return entries


def text_at_revision(revision: str, path: Path) -> str:
    """Read a repository path at a Git revision, returning empty text if absent."""
    result = subprocess.run(
        ["git", "show", f"{revision}:{path.as_posix()}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if result.returncode != 0:
        return ""
    return result.stdout


def helm_sources_from_text(text: str) -> list[HelmSource]:
    """Parse Helm sources from serialized Argo CD Application resources."""
    import yaml

    sources: list[HelmSource] = []
    if not text:
        return sources
    loaded_documents = cast(Iterable[Any], yaml.safe_load_all(text))
    for loaded_document in loaded_documents:
        if isinstance(loaded_document, dict):
            sources.extend(helm_sources(cast(dict[str, Any], loaded_document)))
    return sources


def render_sources(
    sources: Iterable[HelmSource],
    output: Path,
    kubernetes_version: str,
) -> set[str]:
    """Render Helm sources and return images used by their workloads."""
    output.mkdir(parents=True, exist_ok=True)
    images: set[str] = set()
    for index, source in enumerate(sources, start=1):
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
        rendered = run(command)
        target = output / f"helm-{release}-{index}.yaml"
        target.write_text(rendered, encoding="utf-8")
        values_path.unlink(missing_ok=True)
        images.update(workload_image_references(rendered))
    return images


def application_paths(paths: Iterable[Path]) -> list[Path]:
    """Return Argo CD Application paths from a candidate path collection."""
    return sorted(
        path
        for path in paths
        if path.as_posix().startswith("k8s/apps/") and path.name == "application.yaml"
    )


def all_kubernetes_yaml() -> list[Path]:
    """Return every Kubernetes YAML file in the repository layout."""
    return sorted(
        path
        for path in Path("k8s").rglob("*")
        if path.is_file() and path.suffix in {".yaml", ".yml"}
    )


def raw_manifest_paths(paths: Iterable[Path]) -> list[Path]:
    """Return repository-owned raw manifest paths from candidate paths."""
    return sorted(
        path
        for path in paths
        if path.is_file()
        and path.suffix in {".yaml", ".yml"}
        and "/manifests/" in f"/{path.as_posix()}"
    )


def inventory_changed(
    base: str,
    head: str,
    output: Path,
    kubernetes_version: str,
) -> tuple[set[str], set[str]]:
    """Inventory raw and rendered image references changed between revisions."""
    paths = changed_files(base, head)
    render_raw_manifests(raw_manifest_paths(paths), output / "head" / "raw")

    diff = run(
        [
            "git",
            "diff",
            "--unified=0",
            base,
            head,
            "--",
            "k8s/**/*.yaml",
            "k8s/**/*.yml",
        ]
    )
    raw_images = set(added_image_references(diff))
    helm_images: set[str] = set()
    for path in application_paths(paths):
        base_sources = helm_sources_from_text(text_at_revision(base, path))
        head_sources = helm_sources_from_text(text_at_revision(head, path))
        base_images = render_sources(
            base_sources,
            output / "base" / safe_name(path.parent.name),
            kubernetes_version,
        )
        head_images = render_sources(
            head_sources,
            output / "head" / "helm" / safe_name(path.parent.name),
            kubernetes_version,
        )
        helm_images.update(head_images - base_images)
    return raw_images, helm_images


def inventory_all(
    output: Path, kubernetes_version: str
) -> tuple[set[str], set[str]]:
    """Inventory all raw and Helm-rendered deployed image references."""
    paths = all_kubernetes_yaml()
    raw_images = explicit_image_references(paths)
    render_raw_manifests(raw_manifest_paths(paths), output / "head" / "raw")
    sources: list[HelmSource] = []
    for path in application_paths(paths):
        sources.extend(helm_sources_from_text(path.read_text(encoding="utf-8")))
    helm_images = render_sources(
        sources, output / "head" / "helm", kubernetes_version
    )
    return raw_images, helm_images


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("changed", "all"), required=True)
    parser.add_argument("--base")
    parser.add_argument("--head", default="HEAD")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--matrix-output", type=Path, required=True)
    parser.add_argument("--github-output", type=Path)
    parser.add_argument("--kubernetes-version", required=True)
    parser.add_argument("--validate-remote", action="store_true")
    return parser.parse_args()


def main() -> int:
    """Build and optionally validate the requested deployed-image inventory."""
    args = parse_args()
    if args.mode == "changed":
        if not args.base:
            raise ValueError("--base is required in changed mode")
        raw_images, helm_images = inventory_changed(
            args.base,
            args.head,
            args.output,
            args.kubernetes_version,
        )
    else:
        raw_images, helm_images = inventory_all(args.output, args.kubernetes_version)

    for reference in sorted(raw_images):
        validate_explicit_pin(reference)

    entries = matrix_entries(raw_images, helm_images)
    if args.validate_remote:
        for entry in entries:
            print(f"Validating {entry['image']}")
            # A full scheduled audit verifies that every immutable digest remains
            # pullable for linux/amd64. Mutable tag drift is handled by Renovate;
            # changed refs must still prove that their tag and digest agree.
            validate_image(entry["image"], require_tag_match=args.mode == "changed")

    matrix = json.dumps(entries, separators=(",", ":"))
    args.matrix_output.parent.mkdir(parents=True, exist_ok=True)
    args.matrix_output.write_text(matrix + "\n", encoding="utf-8")
    if args.github_output:
        with args.github_output.open("a", encoding="utf-8") as output:
            output.write(f"images={matrix}\n")
    print(
        f"Image inventory: {len(raw_images)} explicit, "
        f"{len(helm_images)} Helm, {len(entries)} unique scan target(s)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
