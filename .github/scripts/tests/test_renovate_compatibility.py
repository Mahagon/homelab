from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).parents[1] / "renovate_compatibility.py"
SPEC = importlib.util.spec_from_file_location("renovate_compatibility", MODULE_PATH)
assert SPEC and SPEC.loader
compatibility = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = compatibility
SPEC.loader.exec_module(compatibility)


class CompatibilityTest(unittest.TestCase):
    def test_parses_single_and_multi_source_applications(self) -> None:
        single = {
            "kind": "Application",
            "metadata": {"name": "replicator"},
            "spec": {
                "source": {
                    "repoURL": "https://example.invalid/charts",
                    "chart": "replicator",
                    "targetRevision": "1.2.3",
                },
                "destination": {"namespace": "kube-system"},
            },
        }
        multi = {
            "kind": "Application",
            "metadata": {"name": "argocd"},
            "spec": {
                "sources": [
                    {
                        "repoURL": "https://example.invalid/charts",
                        "chart": "argocd",
                        "targetRevision": "4.5.6",
                        "helm": {"values": "domain: ${DOMAIN}"},
                    },
                    {"repoURL": "git@example.invalid:repo.git", "path": "manifests"},
                ],
                "destination": {"namespace": "argocd"},
            },
        }

        single_sources = compatibility.helm_sources(single)
        multi_sources = compatibility.helm_sources(multi)

        self.assertEqual(single_sources[0].chart, "replicator")
        self.assertEqual(single_sources[0].namespace, "kube-system")
        self.assertEqual(len(multi_sources), 1)
        self.assertEqual(multi_sources[0].values, "domain: ${DOMAIN}")

    def test_substitutes_known_placeholders_and_preserves_runtime_variables(self) -> None:
        value = compatibility.substitute_placeholders("${DOMAIN} ${EMAIL} ${HACS_VERSION}")
        self.assertEqual(
            value,
            "example.invalid security@example.com ${HACS_VERSION}",
        )

    def test_extracts_unique_added_image_references(self) -> None:
        diff = """--- a/pod.yaml
+++ b/pod.yaml
- image: old/image:1
+          image: ghcr.io/example/app:2@sha256:abc
+          image: ghcr.io/example/app:2@sha256:abc # duplicate
 context: image: ignored/example:1
"""
        self.assertEqual(
            compatibility.added_image_references(diff),
            ["ghcr.io/example/app:2@sha256:abc"],
        )

    def test_platform_detection_ignores_attestations(self) -> None:
        descriptor = {
            "manifests": [
                {"platform": {"os": "unknown", "architecture": "unknown"}},
                {"platform": {"os": "linux", "architecture": "amd64"}},
            ]
        }
        self.assertTrue(compatibility.supports_platform(descriptor, "linux", "amd64"))
        self.assertFalse(compatibility.supports_platform(descriptor, "linux", "arm64"))

    def test_pinned_tag_must_match_digest_and_platform(self) -> None:
        descriptors = {
            "example/app:2@sha256:good": {
                "digest": "sha256:good",
                "manifests": [{"platform": {"os": "linux", "architecture": "amd64"}}],
            },
            "example/app:2": {
                "digest": "sha256:good",
                "manifests": [{"platform": {"os": "linux", "architecture": "amd64"}}],
            },
        }

        def runner(command: list[str]) -> str:
            return json.dumps(descriptors[command[4]])

        compatibility.validate_image("example/app:2@sha256:good", runner)
        descriptors["example/app:2"]["digest"] = "sha256:moved"
        with self.assertRaisesRegex(ValueError, "not the pinned digest"):
            compatibility.validate_image("example/app:2@sha256:good", runner)

    def test_helm_render_failure_propagates(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            application = root / "k8s/apps/example/application.yaml"
            application.parent.mkdir(parents=True)
            application.write_text(
                """kind: Application
metadata:
  name: example
spec:
  source:
    repoURL: https://example.invalid/charts
    chart: example
    targetRevision: 1.2.3
  destination:
    namespace: example
""",
                encoding="utf-8",
            )

            def failing_runner(command: list[str]) -> str:
                raise RuntimeError("helm failed")

            old_cwd = Path.cwd()
            try:
                os.chdir(root)
                with self.assertRaisesRegex(RuntimeError, "helm failed"):
                    compatibility.render_helm_sources(
                        [Path("k8s/apps/example/application.yaml")],
                        root / "output",
                        "1.36.3",
                        failing_runner,
                    )
            finally:
                os.chdir(old_cwd)
