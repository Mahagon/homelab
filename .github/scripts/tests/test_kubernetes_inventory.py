from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


SCRIPTS = Path(__file__).parents[1]
sys.path.insert(0, str(SCRIPTS))
MODULE_PATH = SCRIPTS / "kubernetes_inventory.py"
SPEC = importlib.util.spec_from_file_location("kubernetes_inventory", MODULE_PATH)
assert SPEC and SPEC.loader
inventory = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = inventory
SPEC.loader.exec_module(inventory)


class KubernetesInventoryTest(unittest.TestCase):
    def test_extracts_images_from_containers_and_embedded_yaml(self) -> None:
        """Extract explicit images from ordinary and embedded YAML."""
        manifest = """
containers:
  - name: app
    image: ghcr.io/example/app:2@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
helperPod.yaml: |
  containers:
    - image: busybox:1.38@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
ignored: image: context-only
"""
        self.assertEqual(
            inventory.image_references(manifest),
            {
                "ghcr.io/example/app:2@sha256:" + "a" * 64,
                "busybox:1.38@sha256:" + "b" * 64,
            },
        )

    def test_rendered_inventory_ignores_helm_test_hooks(self) -> None:
        """Exclude Helm test-hook images from the deployed inventory."""
        rendered = """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: app
spec:
  template:
    spec:
      initContainers:
        - name: init
          image: example/init:1
      containers:
        - name: app
          image: example/app:1
---
apiVersion: v1
kind: Pod
metadata:
  name: test
  annotations:
    helm.sh/hook: test
spec:
  containers:
    - name: test
      image: example/test:1
"""
        self.assertEqual(
            inventory.workload_image_references(rendered),
            {"example/app:1", "example/init:1"},
        )

    def test_explicit_images_require_tag_and_digest(self) -> None:
        """Require explicit images to carry readable tags and digests."""
        inventory.validate_explicit_pin("example/app:1@sha256:" + "a" * 64)
        with self.assertRaisesRegex(ValueError, "sha256"):
            inventory.validate_explicit_pin("example/app:1")
        with self.assertRaisesRegex(ValueError, "human-readable tag"):
            inventory.validate_explicit_pin("example/app@sha256:" + "a" * 64)

    def test_matrix_deduplicates_and_scopes_cloudflared_ignore(self) -> None:
        """Deduplicate targets and scope the cloudflared ignore file."""
        cloudflared = "cloudflare/cloudflared:1@sha256:" + "a" * 64
        app = "ghcr.io/example/app:2@sha256:" + "b" * 64
        entries = inventory.matrix_entries({cloudflared, app}, {app})

        self.assertEqual([entry["image"] for entry in entries], [cloudflared, app])
        self.assertEqual(entries[0]["source"], "raw")
        self.assertEqual(entries[0]["ignorefile"], inventory.CLOUDFLARED_IGNORE)
        self.assertEqual(entries[1]["source"], "raw+helm")
        self.assertEqual(entries[1]["ignorefile"], inventory.DEFAULT_IGNORE)

    def test_matrix_prefers_a_pinned_copy_of_the_same_tag(self) -> None:
        """Prefer an immutable reference when raw and Helm tags overlap."""
        pinned = "quay.io/example/app:v1@sha256:" + "a" * 64
        entries = inventory.matrix_entries({pinned}, {"quay.io/example/app:v1"})
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["image"], pinned)
        self.assertEqual(entries[0]["source"], "raw+helm")

    def test_category_is_stable_across_tag_and_digest_updates(self) -> None:
        """Keep Code Scanning categories stable across image updates."""
        old = "ghcr.io/example/app:1@sha256:" + "a" * 64
        new = "ghcr.io/example/app:2@sha256:" + "b" * 64
        self.assertEqual(inventory.scan_category(old), inventory.scan_category(new))

    def test_helm_sources_can_be_loaded_from_historical_text(self) -> None:
        """Load Helm source metadata from historical Application YAML."""
        text = """
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: example
spec:
  source:
    repoURL: https://example.invalid/charts
    chart: example
    targetRevision: 1.2.3
  destination:
    namespace: example
"""
        sources = inventory.helm_sources_from_text(text)
        self.assertEqual(len(sources), 1)
        self.assertEqual(sources[0].chart, "example")


if __name__ == "__main__":
    unittest.main()
