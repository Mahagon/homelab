#!/usr/bin/env python3
"""Enforce a small, explicit runtime-security baseline for owned workloads."""

from __future__ import annotations

import argparse
import datetime as dt
import pathlib
import sys
from dataclasses import dataclass
from typing import Iterable, cast

import yaml


YamlMap = dict[str, object]
WORKLOAD_KINDS = {
    "Pod",
    "Deployment",
    "ReplicaSet",
    "StatefulSet",
    "DaemonSet",
    "Job",
    "CronJob",
}


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


@dataclass(frozen=True, order=True)
class Finding:
    resource: str
    container: str
    control: str
    source: str

    def label(self) -> str:
        """Return a concise human-readable finding label."""
        return f"{self.resource} container={self.container} control={self.control} ({self.source})"


def documents(path: pathlib.Path) -> Iterable[tuple[YamlMap, str]]:
    """Yield top-level and embedded Kubernetes documents with source labels."""
    text = path.read_text(encoding="utf-8")
    loaded_documents = cast(Iterable[object], yaml.safe_load_all(text))
    for index, loaded_document in enumerate(loaded_documents, start=1):
        document = as_mapping(loaded_document)
        if not document:
            continue
        yield document, f"{path.as_posix()}#{index}"
        if document.get("kind") == "ConfigMap":
            data = as_mapping(document.get("data"))
            for key, value in data.items():
                if not isinstance(value, str) or not key.endswith((".yaml", ".yml")):
                    continue
                loaded_embedded = cast(Iterable[object], yaml.safe_load_all(value))
                for embedded_index, loaded_document in enumerate(loaded_embedded, start=1):
                    embedded = as_mapping(loaded_document)
                    if embedded:
                        metadata = as_mapping(embedded.get("metadata"))
                        parent_metadata = as_mapping(document.get("metadata"))
                        metadata.setdefault(
                            "namespace", parent_metadata.get("namespace", "default")
                        )
                        embedded["metadata"] = metadata
                        yield embedded, f"{path.as_posix()}#{index}:{key}#{embedded_index}"


def workload(document: YamlMap) -> tuple[str, YamlMap] | None:
    """Return the resource identity and Pod spec for a workload document."""
    kind = document.get("kind")
    if not isinstance(kind, str) or kind not in WORKLOAD_KINDS:
        return None
    metadata = as_mapping(document.get("metadata"))
    name = metadata.get("name")
    if not isinstance(name, str):
        return None
    namespace = metadata.get("namespace", "default")
    if not isinstance(namespace, str):
        namespace = "default"
    spec = as_mapping(document.get("spec"))
    if kind == "Pod":
        pod = spec
    elif kind == "CronJob":
        job_template = as_mapping(spec.get("jobTemplate"))
        job_spec = as_mapping(job_template.get("spec"))
        template = as_mapping(job_spec.get("template"))
        pod = as_mapping(template.get("spec"))
    else:
        template = as_mapping(spec.get("template"))
        pod = as_mapping(template.get("spec"))
    return f"{kind}/{namespace}/{name}", pod


def findings(paths: Iterable[pathlib.Path]) -> list[Finding]:
    """Collect runtime-policy findings from repository-owned manifests."""
    result: list[Finding] = []
    for path in paths:
        for document, source in documents(path):
            entry = workload(document)
            if entry is None:
                continue
            resource, pod = entry
            pod_security = as_mapping(pod.get("securityContext"))
            if pod.get("automountServiceAccountToken") is not False:
                result.append(Finding(resource, "*", "automount-service-account-token", source))

            pod_seccomp = (
                as_mapping(pod_security.get("seccompProfile")).get("type")
                == "RuntimeDefault"
            )
            pod_non_root = pod_security.get("runAsNonRoot") is True
            for section in ("initContainers", "containers", "ephemeralContainers"):
                for value in as_list(pod.get(section)):
                    container = as_mapping(value)
                    name_value = container.get("name")
                    name = name_value if isinstance(name_value, str) else f"<{section}>"
                    security = as_mapping(container.get("securityContext"))
                    if security.get("privileged") is True:
                        result.append(Finding(resource, name, "privileged", source))
                    if security.get("allowPrivilegeEscalation") is not False:
                        result.append(Finding(resource, name, "allow-privilege-escalation", source))
                    if (
                        not pod_seccomp
                        and as_mapping(security.get("seccompProfile")).get("type")
                        != "RuntimeDefault"
                    ):
                        result.append(Finding(resource, name, "seccomp-runtime-default", source))
                    if not pod_non_root and security.get("runAsNonRoot") is not True:
                        result.append(Finding(resource, name, "run-as-non-root", source))
                    if security.get("readOnlyRootFilesystem") is not True:
                        result.append(Finding(resource, name, "read-only-root-filesystem", source))
                    capabilities = as_mapping(security.get("capabilities"))
                    dropped = {
                        item
                        for item in as_list(capabilities.get("drop"))
                        if isinstance(item, str)
                    }
                    if "ALL" not in dropped:
                        result.append(Finding(resource, name, "drop-all-capabilities", source))
    return sorted(result)


def load_exceptions(path: pathlib.Path, today: dt.date) -> set[tuple[str, str, str]]:
    """Load, validate, and flatten current runtime-policy exceptions."""
    loaded_config = cast(object, yaml.safe_load(path.read_text(encoding="utf-8")))
    config = as_mapping(loaded_config)
    entries: set[tuple[str, str, str]] = set()
    errors: list[str] = []
    for value in as_list(config.get("exceptions")):
        item = as_mapping(value)
        required = ("resource", "container", "controls", "reason", "compensating_control", "expires")
        missing = [key for key in required if not item.get(key)]
        if missing:
            errors.append(f"exception is missing {', '.join(missing)}: {item}")
            continue
        expiry_value = item["expires"]
        if isinstance(expiry_value, str):
            expiry = dt.date.fromisoformat(expiry_value)
        elif isinstance(expiry_value, dt.date):
            expiry = expiry_value
        else:
            errors.append(f"exception has invalid expiry: {item}")
            continue
        if expiry < today:
            errors.append(f"exception expired on {expiry}: {item['resource']} container={item['container']}")
        resource = item["resource"]
        container = item["container"]
        if not isinstance(resource, str) or not isinstance(container, str):
            errors.append(f"exception resource and container must be strings: {item}")
            continue
        for control in as_list(item["controls"]):
            if not isinstance(control, str):
                errors.append(f"exception control must be a string: {item}")
                continue
            key = (resource, container, control)
            if key in entries:
                errors.append(f"duplicate exception: {key}")
            entries.add(key)
    if errors:
        raise ValueError("\n".join(errors))
    return entries


def validate(paths: Iterable[pathlib.Path], exception_path: pathlib.Path, today: dt.date) -> list[str]:
    """Return missing-hardening and stale-exception errors."""
    exceptions = load_exceptions(exception_path, today)
    used: set[tuple[str, str, str]] = set()
    errors: list[str] = []
    for finding in findings(paths):
        key = (finding.resource, finding.container, finding.control)
        if key in exceptions:
            used.add(key)
        else:
            errors.append(f"missing hardening or exception: {finding.label()}")
    for key in sorted(set(exceptions) - used):
        errors.append(f"unused exception: resource={key[0]} container={key[1]} control={key[2]}")
    return errors


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser()
    parser.add_argument("paths", nargs="*", type=pathlib.Path)
    parser.add_argument(
        "--exceptions",
        type=pathlib.Path,
        default=pathlib.Path(".github/security/kubernetes-exceptions.yaml"),
    )
    parser.add_argument("--today", type=dt.date.fromisoformat, default=dt.date.today())
    return parser.parse_args()


def main() -> int:
    """Validate owned Kubernetes workloads against the runtime policy."""
    args = parse_args()
    paths = args.paths or sorted(pathlib.Path("k8s/apps").glob("*/manifests/*.yaml"))
    try:
        errors = validate(paths, args.exceptions, args.today)
    except (OSError, ValueError, yaml.YAMLError) as error:
        print(error, file=sys.stderr)
        return 1
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print(f"Runtime policy passed for {len(paths)} manifest files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
