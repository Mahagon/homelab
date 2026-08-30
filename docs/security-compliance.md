# Security baseline and CIS evidence

This project uses CIS benchmarks as control catalogs, not as a certification
claim. The selected profile is cost-aware and scoped to the new Alexa,
Cloudflare Tunnel, and OpenTofu resources.

- AWS reference: [CIS AWS Foundations Benchmark v5.0.0](https://docs.aws.amazon.com/securityhub/latest/userguide/cis-aws-foundations-benchmark.html)
- K3s reference: [CIS Kubernetes Benchmark v1.12 self-assessment for K3s v1.32-v1.36](https://docs.k3s.io/security/self-assessment-1.12)
- K3s server observed during implementation: `v1.36.3+k3s1`

## AWS cost-aware baseline

| Control area | Status | Evidence or action |
|---|---|---|
| Root MFA and no root access key | Manual | Required during account bootstrap and reviewed annually. |
| Security/billing/operations contacts | Manual | Required during account bootstrap. |
| Human access | Manual | IAM Identity Center/SSO; no project IAM user or permanent key. |
| Workload deployment identity | Implemented | GitHub OIDC trust fixes audience, repository, and protected environment. Sessions last at most one hour. |
| Least privilege | Implemented | Deployment policy is scoped to state, the named Lambda/log group/role, and budget APIs; Lambda can only write its own logs. |
| S3 account public access block | Implemented | All four account-level and bucket-level block settings are enabled. |
| State confidentiality/integrity | Implemented | TLS-only policy, SSE-S3, ownership enforcement, native lockfile, and sensitive outputs. |
| State recovery | Implemented | Versioning, 90-day noncurrent retention, no force destroy, and lifecycle `prevent_destroy`. |
| Cost visibility | Implemented | Monthly USD 1 budget notifying at one percent actual spend. This is an alert, not a service control. |
| CloudTrail management event history | Partial | AWS-provided 90-day event history remains available; no separate paid storage trail is created. |
| Multi-Region CloudTrail and log validation | Deferred due to cost | Required for broader CIS coverage; add when ongoing S3/logging cost is accepted. |
| AWS Config | Deferred due to cost | Required by Security Hub continuous checks and billed per configuration item/evaluation. |
| Security Hub CIS v5 standard | Deferred due to cost | Static IaC checks and this evidence matrix are used instead. |
| Customer-managed KMS keys | Deferred due to cost | AWS-managed/SSE-S3 encryption is used; customer keys have a recurring charge. |
| GuardDuty and X-Ray | Deferred due to cost | No paid continuous threat detection or tracing in the cost-aware profile. |

Because the deferred controls are material, documentation and CI must say
“CIS-aligned cost-aware baseline,” never “CIS compliant.”

## K3s CIS v1.12 workload baseline

| Workload control | Status | New cloudflared implementation |
|---|---|---|
| Namespace boundaries | Implemented | Dedicated `cloudflared` namespace. |
| Pod Security Admission | Implemented | `restricted` enforce, audit, and warn labels apply only to this namespace. |
| Service-account minimization | Implemented | Dedicated account with no RBAC grants and token automount disabled on both account and Pod. |
| Privilege escalation | Implemented | Disabled. |
| Linux capabilities | Implemented | Drop `ALL`; no additions. |
| Root execution | Implemented | Fixed non-root UID/GID 65532. |
| Seccomp | Implemented | `RuntimeDefault` at Pod level. |
| Root filesystem | Implemented | Read-only with a size-limited `/tmp` `emptyDir`. |
| Host namespaces | Implemented | No host network, PID, or IPC access. |
| Resource governance | Implemented | CPU/memory requests and limits, fixed replica count, and no autoscaler. |
| Network segmentation | Implemented | Default deny; explicit DNS, tunnel 7844, and Home Assistant 8123 egress only. |
| Secret handling | Partial | Token is a read-only Secret mount and never stored in Git; K3s secrets-at-rest encryption is outside this scope. |
| Image provenance | Partial | Immutable digest and Renovate tracking; no admission-time signature verification. |
| Availability | Implemented | Two connectors, readiness/liveness probes, rolling update, and PDB. Both replicas share one physical node. |

The K3s network-policy controller is enabled because otherwise the new policies
have no effect. No default-deny policy is applied to existing namespaces.

### Explicit existing exceptions

- Home Assistant uses `hostNetwork` and `NET_ADMIN`/`NET_RAW` for local-device
  discovery. It cannot enter a `restricted` namespace without redesigning that
  discovery path.
- Jellyfin currently runs privileged for its hardware/media requirements.
- Cluster-wide secrets encryption, audit logging, EventRateLimit, and a complete
  CIS node self-assessment are not changed by this project.

These exceptions must remain visible in reports. Do not add broad scanner
ignores that make the whole repository appear compliant.

## Cloud and application threat controls

| Threat | Control |
|---|---|
| Internet scanning of the home network | Tunnel is outbound-only; no Home Assistant WAN NAT/port forward. |
| Bypass of public authentication | Home Assistant authentication/MFA remains mandatory; unauthenticated `/api/` returns 401. |
| Stolen Alexa OAuth token | Lambda neither stores nor logs tokens and forwards them only to the fixed HTTPS Home Assistant endpoint. |
| Arbitrary Lambda invocation | Resource permission requires the Alexa Smart Home service principal and exact Skill ID. |
| Lambda cost amplification | Eight-second timeout, 256 MB memory, and the AWS account-level concurrency quota. |
| Tunnel compromise | Connector token is a sensitive state output and Kubernetes Secret; the pod cannot modify remote routing. Rotate after suspected disclosure. |
| DNS takeover or drift | Dedicated Cloudflare API token, OpenTofu-managed proxied CNAME, ExternalDNS exclusion, and post-apply empty plan. |
| CI credential theft | Short-lived GitHub OIDC credentials, exact trust subject, read-only default workflow permissions, and pinned actions. |
| Accidental broad Alexa exposure | Explicit 14-entity allowlist; no domain/glob includes and no proactive-event credentials. |

Cloudflare Access is intentionally absent from this hostname because it would
intercept Alexa account linking and directives. Home Assistant MFA protects
interactive remote users instead.

## Automated evidence

CI produces reproducible evidence through:

- `tofu fmt`, `validate`, and mocked `tofu test` suites.
- TFLint AWS rules.
- Checkov on the new OpenTofu and cloudflared resources.
- Trivy IaC, image, and repository-wide secret scans.
- Kubeconform schema validation.
- Lambda authorization, error, timeout, and log-redaction unit tests.

OpenTofu input validations, resource preconditions, and test assertions are
blocking. OpenTofu `check` blocks are supplementary cross-resource diagnostics;
their warnings are never the only enforcement for a security invariant.

## Exception governance

Every scanner suppression must identify one rule and resource and include:

1. Why the control is inapplicable or conflicts with the cost profile.
2. The compensating control.
3. A review date no later than one year away.

CI fails all other Checkov findings and HIGH/CRITICAL Trivy findings. Review the
baseline whenever the AWS CIS, K3s CIS, provider, Lambda runtime, or cloudflared
major version changes.
