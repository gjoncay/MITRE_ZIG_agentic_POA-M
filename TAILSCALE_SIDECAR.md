# Tailscale Sidecar — give this app its own URL

**Purpose (for the AI agent reading this):** this project's web app should be
reachable from any device on the owner's tailnet at a clean per-app URL with a
valid certificate:

```
https://<app-name>.dikdik-macaroni.ts.net      # tailnet-only, NOT public internet
```

You do this by adding a **Tailscale sidecar container** next to the app. Each app
gets its own Tailscale node (its own name + Let's Encrypt cert). Follow the recipe
below. Do not expose the app on host ports — it should be reachable *only* through
its Tailscale node.

---

## Application access control

`TS_AUTHKEY` is a Tailscale node-enrollment credential; it is not the web
application's bearer token. For this project's deliberately private,
single-operator Tailnet deployment, set `CSDH_AUTH_MODE=disabled` in the
gitignored `.env` to use Tailnet device access and ACLs as the application
access boundary. The browser will then not ask for a bearer token.

Choose that mode only when the Tailnet, its ACLs, and every reachable device are
controlled by the same operator and this sidecar remains the only ingress. Use
the default `CSDH_AUTH_MODE=token` (or an authenticated trusted proxy) for a
shared Tailnet, multiple operators, or any additional ingress. See
`WEB_DEPLOYMENT_OPERATIONS.md` for the exact authentication and local-model
configuration.

---

## Environment facts (already true on this machine)

- **Tailnet domain:** `dikdik-macaroni.ts.net` (so hostname `foo` → `https://foo.dikdik-macaroni.ts.net`).
- **HTTPS certificates are enabled** for the tailnet (no admin-console step needed).
- **Reusable auth key**: reuse the `TS_AUTHKEY=tskey-auth-…` from another app's
  `.env` (e.g. `~/Projects/whoami/.env`), or mint a new reusable key at
  https://login.tailscale.com/admin/settings/keys. Copy it into THIS project's
  `.env` (gitignored). It's only used at first registration; each node then
  persists its identity in its own volume.
- **Host firewall (ufw) is default-deny incoming** — but the sidecar needs **no**
  firewall rule, because it proxies to the app over loopback inside a shared netns.
- Runs on the owner's **laptop**: the URL only works while the laptop is awake and
  on the tailnet (lid-closed sleep = offline).

---

## Recipe

Fill in these four values, then apply the steps:

| Placeholder | Meaning | Example |
|---|---|---|
| `<APP>` | the app's compose service name | `grafana` |
| `<NAME>` | desired hostname = the URL subdomain | `grafana` → grafana.dikdik-macaroni.ts.net |
| `<PORT>` | the port the app listens on **inside its container** | `3000` |
| `<SCHEME>` | `http` if the app is plain HTTP; `https+insecure` if the app serves its own TLS (self-signed) | `http` |

### 1. Add the sidecar to `docker-compose.yml`

```yaml
  # Tailscale sidecar for <APP> -> https://<NAME>.dikdik-macaroni.ts.net
  <APP>-ts:
    image: tailscale/tailscale:latest
    restart: unless-stopped
    network_mode: service:<APP>          # shares <APP>'s netns -> proxy to 127.0.0.1:<PORT>
    environment:
      - TS_AUTHKEY=${TS_AUTHKEY:?set TS_AUTHKEY in .env}
      - TS_HOSTNAME=<NAME>               # becomes the URL subdomain
      - TS_STATE_DIR=/var/lib/tailscale
      - TS_USERSPACE=true                # no NET_ADMIN / /dev/net/tun needed
      - TS_SERVE_CONFIG=/config/<NAME>.json
    volumes:
      - <APP>tsdata:/var/lib/tailscale
      - ./tailscale/<NAME>.json:/config/<NAME>.json:ro
```

Add the named volume too:

```yaml
volumes:
  <APP>tsdata:
```

### 2. Create the serve config `./tailscale/<NAME>.json`

```json
{
  "TCP": { "443": { "HTTPS": true } },
  "Web": {
    "${TS_CERT_DOMAIN}:443": {
      "Handlers": {
        "/": { "Proxy": "<SCHEME>://127.0.0.1:<PORT>" }
      }
    }
  }
}
```

`${TS_CERT_DOMAIN}` is expanded by the Tailscale container to the node's full
MagicDNS name — leave it literally as written.

### 3. Put the auth key in `.env`

```
TS_AUTHKEY=<copy the tskey-auth-… value from ~/Projects/ts-apps/.env>
```
Ensure `.env` is in `.gitignore`.

### 4. Bring up the sidecar

```bash
# if the app is already running:
docker compose up -d --no-deps <APP>-ts
# (or `docker compose up -d` to start the whole project)
```

### 5. Pre-warm the cert (avoids a transient warning on the phone)

The cert is provisioned lazily on the first request (~60–90s). Trigger it from the
host so the owner's first phone visit is instant and clean:

```bash
curl -sI --max-time 120 https://<NAME>.dikdik-macaroni.ts.net/
```

### 6. Verify (do this before telling the owner it's ready)

```bash
# Trusted cert (no -k) + reaches the app:
curl -sI --max-time 25 https://<NAME>.dikdik-macaroni.ts.net/ | grep -iE '^HTTP'
# Cert is real Let's Encrypt for the right name:
echo | openssl s_client -connect <NAME>.dikdik-macaroni.ts.net:443 \
  -servername <NAME>.dikdik-macaroni.ts.net 2>/dev/null \
  | openssl x509 -noout -issuer -subject
```
Expect an `HTTP/2 200` or `302`, issuer `Let's Encrypt`, subject
`CN=<NAME>.dikdik-macaroni.ts.net`. Also confirm the node is up:
`tailscale status | grep <NAME>`.

---

## Gotchas (already learned — don't repeat them)

1. **Do NOT set compose `hostname:` on the sidecar.** It conflicts with
   `network_mode: service:<APP>` and Docker errors out. Use `TS_HOSTNAME` instead.
2. **First visit shows a transient untrusted-cert warning (~60–90s)** while ACME
   runs. That's why step 5 pre-warms it. If a browser cached the failure, fully
   close and reopen the tab. Confirm with
   `docker compose logs <APP>-ts | grep cert` → look for `got cert`.
3. **`<SCHEME>` matters.** Use `https+insecure` only when the backend speaks TLS
   with a self-signed cert (e.g. Kibana on 5601). Most apps are plain `http`.
4. **`<PORT>` is the in-container port**, not a host-published port. The app needs
   no `ports:` mapping at all — Tailscale is the only ingress.
5. **No ufw rule needed.** Serve terminates TLS in `tailscaled` and proxies over
   loopback, which the firewall doesn't filter.
6. If the tailnet has **device approval** on, the new node may need a one-time
   approval in the admin console (it appears as "needs approval").
7. **Recreating `<APP>` (e.g. `--force-recreate <APP>` after a rebuild) orphans
   `<APP>-ts`.** `network_mode: service:<APP>` binds the sidecar to the app
   container's *ID* at sidecar-start time, not to the service name generically.
   Once `<APP>` gets a new container ID, `<APP>-ts` keeps running but its
   tailscaled loses connectivity (logs show `connectivity impacted` /
   `no-derp-connection` flapping in a loop) and `docker compose restart
   <APP>-ts` fails outright (`joining network namespace of container: No such
   container: <old-id>`). Fix: `docker compose up -d --force-recreate <APP>-ts`
   right after recreating `<APP>` — always redeploy both together, never just
   the app.

## Removing / renaming
- Stop serving: remove the `<APP>-ts` service (or `docker compose down`).
- Fully remove the node identity: `docker compose down -v` (wipes the
  `<APP>tsdata` volume) **and** delete the device in the Tailscale admin console.
- Rename the URL: change `TS_HOSTNAME` + the serve filename, then
  `docker compose up -d --force-recreate <APP>-ts` (a new node/cert is created).

## Worked example (Grafana, plain HTTP on :3000)
`<APP>=grafana`, `<NAME>=grafana`, `<PORT>=3000`, `<SCHEME>=http` →
`./tailscale/grafana.json` proxies `http://127.0.0.1:3000`, sidecar service
`grafana-ts`, volume `grafanatsdata` → `https://grafana.dikdik-macaroni.ts.net`.
