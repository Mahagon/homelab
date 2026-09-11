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
