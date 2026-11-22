# K3s upgrade

`update-k3s.timer` (see `butane/config.bu`) installs patch releases of the
current minor version every week. Use this runbook to move to the next minor
version, one minor at a time. Read the K3s release notes and the Kubernetes
"Urgent Upgrade Notes" before you start.

## Back up the kine sqlite datastore

The cluster runs kine on sqlite instead of etcd, so this directory holds the
cluster state. Stop K3s first so the copy is consistent. Running pods keep
running while K3s is stopped.

```shell
sudo systemctl stop k3s
sudo cp -a /var/lib/rancher/k3s/server/db \
 /var/lib/rancher/k3s/server/db.bak-$(date +%Y%m%d-%H%M%S)
```

## Check the current version

```shell
sudo k3s --version
```

## Upgrade to the latest patch of v1.37

`k3s-selinux` is already layered on Fedora CoreOS and rpm-ostree updates it
with the OS. Without `INSTALL_K3S_SKIP_SELINUX_RPM=true` the installer layers
it again, waits for a reboot, and leaves K3s stopped.

```shell
curl -sfL https://get.k3s.io | \
 INSTALL_K3S_VERSION="$(curl -sfL https://update.k3s.io/v1-release/channels/v1.37 -o /dev/null -w '%{url_effective}' | grep -oP 'v[0-9]+\.[0-9]+\.[0-9]+\+k3s[0-9]+$')" \
 INSTALL_K3S_EXEC="server" \
 INSTALL_K3S_SKIP_SELINUX_RPM=true \
 sh -
```

If `systemctl is-active k3s` does not report `active` afterwards, run
`sudo systemctl start k3s`.

## Verify

```shell
sudo k3s --version
kubectl get nodes
kubectl get pods -A | grep -vE 'Running|Completed'
kubectl get applications -n argocd
```

## Update CI

Set `KUBERNETES_VERSION` in `.github/workflows/security-iac.yml` and
`.github/workflows/renovate-compatibility.yml` to the new version so
kubeconform and the Helm renders use matching schemas.
