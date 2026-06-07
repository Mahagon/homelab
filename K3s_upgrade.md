# K3s upgrade

## Backup the kine sqlite datastore (you don't run etcd, so this is your "state")

sudo cp -a /var/lib/rancher/k3s/server/db \
 /var/lib/rancher/k3s/server/db.bak-$(date +%Y%m%d-%H%M%S)

## Confirm current version (sanity check)

sudo k3s --version

## Upgrade — channel form picks the latest stable patch in v1.36

curl -sfL <https://get.k3s.io> | \
 INSTALL_K3S_VERSION="$(curl -sfL https://update.k3s.io/v1-release/channels/v1.36 -o /dev/null -w '%{url_effective}' | grep -oP 'v[0-9]+\.[0-9]+\.[0-9]+\+k3s[0-9]+$')" \
 INSTALL_K3S_EXEC="server" \
 sh -
sudo systemctl daemon-reload
sudo systemctl restart k3s

## Verify

sudo k3s --version
kubectl get nodes
