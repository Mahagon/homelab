# Zählerstände: Grist for the yearly meter-reading comparison

Once a year the neighbours on our street compare meter readings (water,
electricity, heat in kWh, firewood in Raummeter, gas in m³, heat pumps). They
enter the readings themselves at `https://zaehlerstaende.<your-domain>` and get
per-year charts.

The site is [Grist](https://github.com/gristlabs/grist-core) (`gristlabs/grist-oss`,
pinned by digest, updated by Renovate) in the `grist` namespace. Nothing is
built in this repository.

## Security model

- **Cloudflare Access gates the whole hostname.** Only addresses in the
  `ZAEHLERSTAENDE_ALLOWED_EMAILS` secret can sign in, with a one-time PIN sent
  by email. Unauthenticated requests never reach Grist.
- **cloudflared enforces the Access JWT** (`origin_request.access.required`)
  for this route. Even if the Access application were deleted, the connector
  would reject the requests, not forward them.
- **Grist trusts `Cf-Access-Authenticated-User-Email`** for identity
  (`GRIST_FORWARD_AUTH_HEADER`, `GRIST_IGNORE_SESSION`). Only cloudflared is
  safe to forward that header, so Grist has no Traefik Ingress and no LAN
  hostname. Its NetworkPolicy admits only cloudflared. Never add an Ingress:
  any LAN client could then forge the header and act as any user, including
  the admin.
- **No egress.** Formulas run in gVisor without a network. The namespace
  denies all egress, so a compromised pod reaches neither the LAN, the
  cluster, nor the internet.
- **gVisor without a checkpoint.** The Deployment replaces the image's
  `sandbox/run.sh` so that it skips the gVisor engine checkpoint. Restoring
  that checkpoint needs the XSAVE CPU feature, which the node's Celeron J1900
  lacks; with it, every document failed to open with `incompatible
  FeatureSet`. Plain gVisor works, and each document's sandbox just takes a
  little longer to start. Recheck the override against `run.sh` on Grist
  upgrades.
- **Restricted Pod Security.** The pod runs as non-root with a read-only root
  filesystem and no capabilities. Its only exceptions are a `/persist` PVC and
  a `/tmp` emptyDir.
- **Edge rules.** The hostname shares the tunnel WAF rules, the Germany-only
  geo allowlist, the cache bypass, and HSTS/`nosniff`. It needs no rate-limit
  entry because Access handles sign-in.
- **Privacy.** The neighbours' addresses live in a GitHub environment secret
  and in the encrypted OpenTofu state, never in git. CI masks each address
  individually. Alloy redacts email addresses and the Grist boot key from
  `grist` pod logs before shipping them to Grafana Cloud.

The SQLite home database and the `.grist` documents live on the `grist-data`
PVC (SSD), which the daily Restic backup covers.

## One-time setup

1. **Zero Trust organization.** In the Cloudflare dashboard, open Zero Trust,
   choose a team name (`<team>.cloudflareaccess.com`) and the Free plan. Under
   **Settings > Authentication**, add the **One-time PIN** login method.
2. **API token.** Add **Access: Apps and Policies: Edit** (account) to the
   dedicated OpenTofu Cloudflare token.
3. **GitHub `aws-production` environment.**
   - Variable `CLOUDFLARE_ACCESS_TEAM_NAME`: the bare team name.
   - Secret `ZAEHLERSTAENDE_ALLOWED_EMAILS`: a JSON array that includes your
     own address (the cluster `EMAIL`, which becomes the Grist admin):

     ```bash
     gh secret set ZAEHLERSTAENDE_ALLOWED_EMAILS --repo Mahagon/homelab --env aws-production
     # paste: ["you@example.com","neighbour@example.org"]
     ```

   Set both before merging. Otherwise the deploy job's plan fails.
4. **Merge to `main`.** Argo CD deploys `k8s/apps/grist`, and the deploy job
   creates the Access application and policy, the tunnel route, and (with
   `PUBLISH_DNS=true`) the proxied CNAME.
5. **Verify.**
   - From a phone on mobile data, `https://zaehlerstaende.<your-domain>`
     shows the Access login. A non-listed address receives no PIN.
   - After signing in, you land in the `nachbarn` team site as owner.
   - Create a test document and enter the formula `glob.glob('/etc/*')`. It
     must return an empty list, which proves formulas run in the gVisor
     sandbox.
   - `curl -sI https://zaehlerstaende.<your-domain>/status` without a
     cookie is redirected to `<team>.cloudflareaccess.com`.

Optional hardening after the first successful start: also set
`GRIST_PERSONAL_ORGS=false` and `GRIST_ORG_CREATION_ANYONE=false` in
`k8s/apps/grist/manifests/grist.yaml`. Grist 1.7.21 refuses to initialize an
empty database with either flag (`No example workspace available`), but it
accepts them once the database exists. Without them, a signed-in neighbour
can create an empty personal or team site, but cannot see anything they were
not invited to.

## Adding or removing a neighbour

Update the `ZAEHLERSTAENDE_ALLOWED_EMAILS` secret, then run the workflow
manually with `apply=true`, or wait for the next infrastructure change. Also
add or remove them in Grist under **Manage users** of the `nachbarn` site. Do
this as an Editor, so that they cannot change the structure.

## Suggested document layout

One document, `Zählerstände`, with these tables:

| Table          | Columns                                                                                                            |
| -------------- | ------------------------------------------------------------------------------------------------------------------ |
| `Haushalte`    | `Name`, `Email`, `Wohnflaeche_m2`, `Personen`                                                                      |
| `Jahre`        | `Jahr` (integer), `Abgeschlossen` (toggle)                                                                         |
| `Faktoren`     | `Traeger` (Strom, Gas, Holz Buche, Holz Fichte, Wärme, Wasser), `Einheit`, `kWh_pro_Einheit`                       |
| `Ablesungen`   | `Haushalt` (ref), `Jahr` (ref), `Traeger` (ref → Faktoren), `Stand`, plus the formula and trigger columns below    |

Formula columns in `Ablesungen`:

```python
# Email (used by the access rules)
$Haushalt.Email

# Gesperrt
$Jahr.Abgeschlossen

# Verbrauch: this year's reading minus last year's for the same meter
prev = Ablesungen.lookupOne(Haushalt=$Haushalt, Traeger=$Traeger, Jahr=Jahre.lookupOne(Jahr=$Jahr.Jahr - 1))
$Stand - prev.Stand if prev else None

# kWh
$Verbrauch * $Traeger.kWh_pro_Einheit if $Verbrauch is not None else None

# kWh_pro_m2
$kWh / $Haushalt.Wohnflaeche_m2 if $kWh and $Haushalt.Wohnflaeche_m2 else None
```

For firewood, enter the Raummeter bought or burned per year as `Stand`, and
use `$Stand` instead of the difference. Starting points for the factors: gas
≈ 10–11 kWh/m³ (calorific value × Zustandszahl from the gas bill), beech
≈ 1,900–2,100 kWh/rm, spruce ≈ 1,400–1,500 kWh/rm.

Add two trigger-formula columns, `Geaendert_von` (`user.Email`) and
`Geaendert_am` (`NOW()`). Set both to recalculate on any change to the
row, so every row shows who last edited it.

Add chart widgets on a `Vergleich` page, for example kWh/m² per household
grouped by `Jahr`, one chart per `Traeger`.

### Access rules

Under **Access Rules**:

1. **Special rules:** allow structure edits only for owners (`user.Access == OWNER`).
2. **`Ablesungen`:**
   - `user.Access == OWNER` → allow all.
   - `rec.Gesperrt` → deny update and delete. Closing a year in `Jahre`
     freezes its readings.
   - `newRec.Email != user.Email` → deny create and update. Neighbours can
     only enter and edit their own readings.
   - `rec.Email != user.Email` → deny delete.
   - Everyone else → allow read.
3. **`Geaendert_von`, `Geaendert_am`, `Email`, `Gesperrt` columns:** deny
   update for everyone except owners.
4. **`Haushalte`, `Jahre`, `Faktoren`:** read-only for non-owners.

For an anonymous comparison, hide `Haushalte.Name` and `Email` from
non-owners and show a per-household pseudonym instead.

### Audit trail

**Document History > Activity** lists recent changes with user, time, and old
and new values. Grist trims that history, and `grist-core` has no external
audit-log streaming. The trigger columns, the year lock, and the daily backup
therefore serve as the durable record.
