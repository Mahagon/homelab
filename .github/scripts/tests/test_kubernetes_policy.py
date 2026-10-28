import datetime as dt
import pathlib
import sys
import tempfile
import unittest

SCRIPTS = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))

from kubernetes_policy import Finding, findings, validate  # noqa: E402


GOOD = """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: demo
  namespace: apps
spec:
  template:
    spec:
      automountServiceAccountToken: false
      securityContext:
        runAsNonRoot: true
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: demo
          image: example.invalid/demo:1
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: [ALL]
"""


class KubernetesPolicyTests(unittest.TestCase):
    def test_compliant_workload_has_no_findings(self):
        """Accept a workload that satisfies every runtime control."""
        with tempfile.TemporaryDirectory() as directory:
            manifest = pathlib.Path(directory) / "manifest.yaml"
            manifest.write_text(GOOD, encoding="utf-8")
            self.assertEqual([], findings([manifest]))

    def test_reports_each_missing_control(self):
        """Report each independently missing runtime control."""
        with tempfile.TemporaryDirectory() as directory:
            manifest = pathlib.Path(directory) / "manifest.yaml"
            manifest.write_text(
                GOOD.replace("automountServiceAccountToken: false", "automountServiceAccountToken: true")
                .replace("allowPrivilegeEscalation: false", "privileged: true")
                .replace("runAsNonRoot: true", "runAsNonRoot: false"),
                encoding="utf-8",
            )
            controls = {finding.control for finding in findings([manifest])}
            self.assertEqual(
                {
                    "allow-privilege-escalation",
                    "automount-service-account-token",
                    "privileged",
                    "run-as-non-root",
                },
                controls,
            )

    def controls_for(self, manifest_text: str) -> set[str]:
        """Return the finding controls for a single manifest."""
        with tempfile.TemporaryDirectory() as directory:
            manifest = pathlib.Path(directory) / "manifest.yaml"
            manifest.write_text(manifest_text, encoding="utf-8")
            return {finding.control for finding in findings([manifest])}

    def test_container_cannot_override_pod_hardening(self):
        """Report container settings that weaken compliant pod defaults."""
        weakened = GOOD.replace(
            "            allowPrivilegeEscalation: false\n",
            "            allowPrivilegeEscalation: false\n"
            "            runAsNonRoot: false\n"
            "            seccompProfile:\n"
            "              type: Unconfined\n",
        )
        self.assertEqual({"run-as-non-root", "seccomp-runtime-default"}, self.controls_for(weakened))

    def test_root_user_is_reported_even_with_run_as_non_root(self):
        """Treat an explicit UID 0 as a root workload."""
        root_user = GOOD.replace(
            "        runAsNonRoot: true\n", "        runAsNonRoot: true\n        runAsUser: 0\n"
        )
        self.assertEqual({"run-as-non-root"}, self.controls_for(root_user))

    def test_container_level_hardening_satisfies_controls(self):
        """Accept seccomp and non-root settings set only on the container."""
        container_only = GOOD.replace(
            "      securityContext:\n        runAsNonRoot: true\n"
            "        seccompProfile:\n          type: RuntimeDefault\n",
            "",
        ).replace(
            "            allowPrivilegeEscalation: false\n",
            "            allowPrivilegeEscalation: false\n"
            "            runAsNonRoot: true\n"
            "            seccompProfile:\n"
            "              type: RuntimeDefault\n",
        )
        self.assertEqual(set(), self.controls_for(container_only))

    def test_reports_host_access(self):
        """Report host namespaces, hostPath volumes, and added capabilities."""
        host_access = GOOD.replace(
            "      automountServiceAccountToken: false\n",
            "      automountServiceAccountToken: false\n"
            "      hostPID: true\n"
            "      volumes:\n"
            "        - name: host\n"
            "          hostPath: {path: /var/lib}\n",
        ).replace("drop: [ALL]", "drop: [ALL]\n              add: [SYS_ADMIN]")
        self.assertEqual(
            {"host-namespaces", "host-path-volumes", "added-capabilities"},
            self.controls_for(host_access),
        )

    def test_net_bind_service_may_be_added(self):
        """Allow the one capability Pod Security restricted permits."""
        bind = GOOD.replace("drop: [ALL]", "drop: [ALL]\n              add: [NET_BIND_SERVICE]")
        self.assertEqual(set(), self.controls_for(bind))

    def test_exception_must_be_current_and_used(self):
        """Accept current used exceptions and reject expired ones."""
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            manifest = root / "manifest.yaml"
            manifest.write_text(
                GOOD.replace("            readOnlyRootFilesystem: true\n", ""), encoding="utf-8"
            )
            exceptions = root / "exceptions.yaml"
            exceptions.write_text(
                """exceptions:
  - resource: Deployment/apps/demo
    container: demo
    controls: [read-only-root-filesystem]
    reason: Writes generated state.
    compensating_control: Dedicated unprivileged container.
    expires: 2027-01-01
""",
                encoding="utf-8",
            )
            self.assertEqual([], validate([manifest], exceptions, dt.date(2026, 1, 1)))
            with self.assertRaisesRegex(ValueError, "expired"):
                validate([manifest], exceptions, dt.date(2028, 1, 1))

    def test_embedded_helper_pod_is_checked(self):
        """Apply runtime policy to helper Pods embedded in ConfigMaps."""
        with tempfile.TemporaryDirectory() as directory:
            manifest = pathlib.Path(directory) / "manifest.yaml"
            manifest.write_text(
                """kind: ConfigMap
metadata: {name: helper}
data:
  helper.yaml: |
    kind: Pod
    metadata: {name: helper, namespace: storage}
    spec:
      containers:
        - name: helper
          image: busybox:1
""",
                encoding="utf-8",
            )
            self.assertIn(
                Finding(
                    "Pod/storage/helper",
                    "*",
                    "automount-service-account-token",
                    f"{manifest.as_posix()}#1:helper.yaml#1",
                ),
                findings([manifest]),
            )


if __name__ == "__main__":
    unittest.main()
