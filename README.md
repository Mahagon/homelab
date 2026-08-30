# Homelab - Fedora CoreOS + K3s + ArgoCD

Declarative home lab running on a GA-J1900N-D3V (8GB RAM, 256GB SSD, 4TB HDD).

## Architecture

```mermaid
flowchart TD
    Internet["Internet"] -->|HTTPS| Traefik
    RemoteUsers["Remote users / Alexa"] -->|HTTPS| CloudflareTunnel["Cloudflare Tunnel"]
    Git["Git repository"] -->|GitOps| ArgoCD
    ExternalDNS -->|A records| Cloudflare["Cloudflare DNS"]
    CertManager -->|DNS-01 challenge| Cloudflare

    Hardware["GA-J1900N-D3V - 8 GB RAM"] --> FedoraCoreOS["Fedora CoreOS"]
    FedoraCoreOS --> K3s["K3s cluster"]
    K3s --> ArgoCD["Argo CD"]
    K3s --> Traefik["Traefik ingress"]
    K3s --> CertManager["cert-manager"]
    K3s --> ExternalDNS["external-dns"]
    K3s --> Cloudflared["cloudflared - 2 connectors"]
    K3s --> Replicator["kubernetes-replicator"]
    K3s --> VPA["Vertical Pod Autoscaler"]
    K3s --> AppServices["Application services"]
    AppServices --> HomeAssistant["Home Assistant"]

    Traefik --> AppServices
    ArgoCD -->|reconciles| AppServices
    Replicator -->|syncs secrets| AppServices
    VPA -->|adjusts resources| AppServices
    Cloudflared -->|internal HTTP 8123| HomeAssistant

    SSD["SSD 256 GB - OS, K3s state, fast PVs"]
    HDD["HDD 4 TB - media, documents"]
    USB["USB 4 TB - backups, optional"]

    AppServices --> SSD
    AppServices --> HDD
    CloudflareTunnel -->|outbound tunnel| Cloudflared
```

## Prerequisites

- USB flash drive for FCOS installation
- Cloudflare account + least-privilege API tokens (DNS Read/Write and Zone Read; the
  Home Assistant OpenTofu token also needs Tunnel, Zone WAF, Cache Settings,
  Transform Rules, Account Rulesets/Filter Lists, and Zone Settings Write)
- kubectl + helm CLI
- A workstation on the same network
- Amazon Developer account and AWS account for the Alexa Smart Home Lambda
  integration

## Setup Order

### 1. Install Fedora CoreOS

**Transpile the Butane config to Ignition:**

```bash
# Add your SSH public key to butane/config.bu first, then:
podman run --interactive --rm \
  quay.io/coreos/butane:release \
  --pretty --strict < butane/config.bu > butane/config.ign
```

**Create a bootable USB stick:**

```bash
# Download the latest stable FCOS ISO
podman run --privileged --rm \
  -v .:/data -w /data \
  quay.io/coreos/coreos-installer:release \
  download -s stable -p metal -f iso

# Write the ISO to your USB stick (replace /dev/sdX - double-check with lsblk!)
sudo dd if=fedora-coreos-*.iso of=/dev/sdX bs=4M status=progress oflag=sync
```

**Install to disk:**

1. Boot the machine from the USB stick (live environment)
2. Set keyboard layout if needed (e.g. German layout):

   ```bash
   sudo loadkeys de
   ```

3. Serve the Ignition file from your workstation:

   ```bash
   # Open port 8080 through the firewall temporarily
   sudo firewall-cmd --add-port=8080/tcp

   python3 -m http.server 8080  # run in the butane/ directory
   ```

4. Verify the target drive (look for your 256GB SSD):

   ```bash
   lsblk -o NAME,SIZE,MODEL,TRAN
   ```

5. If the disk has existing LVM volumes, deactivate them first:

   ```bash
   sudo vgchange -an
   ```

6. On the booted machine, install to the SSD (replace `sda` if needed):

   ```bash
   sudo coreos-installer install /dev/sda \
      --insecure-ignition \
     --ignition-url http://<workstation-ip>:8080/config.ign
   ```

7. Close the firewall port on your workstation:

   ```bash
   sudo firewall-cmd --remove-port=8080/tcp
   ```

8. Reboot - K3s installs automatically on first boot via the `install-k3s.service` unit

### 2. Generate SSH key for ArgoCD repo access

The bootstrap script uses `~/.ssh/id_ed25519_argocd` to give ArgoCD read access to this repo.
Run the following on your **workstation** (not the homelab) to generate the key pair:

```bash
ssh-keygen -t ed25519 -C "argocd@homelab" -f ~/.ssh/id_ed25519_argocd
```

Then add the public key as a deploy key on GitHub (`github.com/Mahagon/homelab`):

1. Go to **Settings → Deploy keys → Add deploy key**
2. Paste the contents of `~/.ssh/id_ed25519_argocd.pub`
3. Name it `argocd-homelab`, leave **Allow write access** unchecked
4. Click **Add key**

> Leave the passphrase empty - ArgoCD reads the key automatically and cannot prompt for one.

### 3. Bootstrap ArgoCD

```bash
ssh core@<your-server-ip>
# K3s is auto-installed via Ignition - verify:
sudo systemctl status k3s

# From your workstation, copy the kubeconfig:
scp core@<server-ip>:/etc/rancher/k3s/k3s.yaml ~/.kube/config
# Fix the server address in the kubeconfig

# Bootstrap ArgoCD + secrets.
# The script will prompt for GitHub OAuth credentials for ArgoCD and Paperless-ngx.
cd k8s/bootstrap/
DOMAIN=example.com EMAIL=you@example.com REPO_URL=git@github.com:Mahagon/homelab.git \
  ./install-argocd.sh
```

### 4. Deploy the App-of-Apps

```bash
kubectl apply -f k8s/apps/app-of-apps.yaml
# ArgoCD will now reconcile all applications
```

Secrets are handled automatically - no manual secret creation needed after bootstrap:

- **mittwald/kubernetes-secret-generator** generates random passwords on first sync
- **kubernetes-replicator** pushes the PostgreSQL and Redis passwords to app namespaces

DNS records are created automatically by external-dns once it starts.

For outbound-only Home Assistant remote access and the private German Alexa
integration, follow [docs/home-assistant-alexa.md](docs/home-assistant-alexa.md).
The associated cost-aware CIS evidence and exceptions are documented in
[docs/security-compliance.md](docs/security-compliance.md).

### 5. Run Tests

```bash
cd tests/
pip install -r requirements.txt
HOMELAB_DOMAIN=example.com pytest -v
```

## Storage Layout

| Mount              | Disk | StorageClass     | Purpose                                       |
| ------------------ | ---- | ---------------- | --------------------------------------------- |
| `/`                | SSD  | -                | Fedora CoreOS root (read-only)                |
| `/var`             | SSD  | -                | K3s state, container images, ArgoCD           |
| `/var/lib/homelab` | SSD  | `local-path-ssd` | Fast PVs: PostgreSQL, Redis, config volumes   |
| `/var/mnt/data`    | HDD  | `local-path-hdd` | Bulk PVs: Jellyfin media, Paperless documents |
| `/var/mnt/backup`  | USB  | -                | Backup target (optional, nofail mount)        |

## Backup

Daily incremental backups via restic at 01:00 (before the Zincati update window on Sunday 03:00–05:00).

```mermaid
flowchart LR
    Cron["homelab-backup CronJob - daily at 01:00"] --> PG["pg_dumpall - postgres:18-alpine"]
    Cron --> R["restic/restic"]
    PG -->|dump.sql in emptyDir| R

    SSD["/var/lib/homelab - SSD PVCs"] -->|tag: pvcs-ssd| R
    HDD["/var/mnt/data - HDD PVCs"] -->|tag: pvcs-hdd| R
    USB["/var/mnt/backup/restic-repo - USB 4 TB"]

    R -->|tag: postgresql| USB
    R --> USB
```

**Retention policy:** 7 daily · 4 weekly · 6 monthly snapshots per tag.

**Restore a snapshot:**

```bash
# List snapshots
kubectl run restic-restore --rm -it --restart=Never \
  --image=restic/restic:latest \
  --env="RESTIC_REPOSITORY=/backup/restic-repo" \
  --env="RESTIC_PASSWORD=<password-from-secret>" \
  --overrides='{"spec":{"volumes":[{"name":"backup","hostPath":{"path":"/var/mnt/backup"}}],"containers":[{"name":"restic-restore","image":"restic/restic:latest","command":["restic","snapshots"],"volumeMounts":[{"name":"backup","mountPath":"/backup"}]}]}}' \
  -- restic snapshots

# Get restic password
kubectl get secret restic-credentials -n backup -o jsonpath='{.data.password}' | base64 -d
```

## Service URLs (after deployment)

| Service        | URL                                    |
| -------------- | -------------------------------------- |
| ArgoCD         | `https://argocd.<your-domain>`         |
| Home Assistant | `https://homeassistant.<your-domain>`  |
| Jellyfin       | `https://jellyfin.<your-domain>`       |
| Paperless-ngx  | `https://paperless.<your-domain>`      |
| Vaultwarden    | `https://vault.<your-domain>`          |
| PostgreSQL     | Internal only (ClusterIP on port 5432) |
| Redis          | Internal only (ClusterIP on port 6379) |
