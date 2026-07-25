# urnetwork-operator-proxy

Operator tooling for urnetwork network operators.

## egress-prober

Determines each provider's **egress** location without paying for a commercial
IP-geolocation database.

For every provider, the prober opens a tunnel pinned to that provider, runs
geolocation lookups **through** it against three independent free sources, takes
a consensus, and submits the result to the operator's server.

- The prober host never queries a geolocation api directly — every lookup
  egresses through a provider, so the api reports *that provider's* location.
- The lookups are TLS-pinned, so a provider on the path cannot forge a location.
- Country is the trusted output. City is recorded only when at least two sources
  agree (free sources disagree on city often), otherwise the location is
  country-granular.
- A provider that refuses to carry the probe is simply not located; the server
  falls back to its own database.

### Build

```bash
go build ./cmd/egress-prober
```

### Run

```bash
./egress-prober \
  -api-url https://api.example.net \
  -platform-url wss://connect.example.net \
  -by-jwt "$UR_PROBER_BY_JWT" \
  -operator-secret "$UR_OPERATOR_SECRET" \
  -concurrency 4 \
  -cache-ttl 24h \
  -interval 1h
```

`-by-jwt` and `-operator-secret` may also be supplied via the
`UR_PROBER_BY_JWT` and `UR_OPERATOR_SECRET` environment variables instead of
flags, which is the recommended way to run this under systemd (keeps secrets
out of `ps`/shell history). All four of `-api-url`, `-platform-url`, `-by-jwt`
and `-operator-secret` are required; the prober exits immediately with a
message naming the missing flag(s) if any are absent, rather than starting in
a broken state.

The prober needs its own network client identity (`-by-jwt`), provisioned like
any other client. `-operator-secret` must match `ingest_secret` in the server's
`provider_egress.yml` vault resource.

Run `./egress-prober -h` for the full flag list, including `-probe-timeout`
(per-provider probe timeout, must be positive) and `-interval 0` (run a
single pass and exit, useful for driving the prober from an external
cron/systemd timer instead of its own sleep loop; `-interval` must not be
negative).

Each pass enumerates providers broadly and stably: it fetches every
location that currently has at least one provider from the operator's
server, then asks for the providers at each of those locations and unions
the results. This is deliberate — asking for only the server's own
"best available" guess would enumerate exactly the providers the server's
geo database *already* believes are in a given place, which is the inverse
of what a location-correcting probe needs to cover.

**Exit codes**, relevant when driving `-interval 0` from cron/systemd:
the process exits non-zero if the provider list could not be fetched at
all, or if a pass completed having submitted nothing while recording at
least one failure (e.g. every probe failed the same way — a wrong
`-platform-url`, a revoked jwt). A pass with nothing to do (no providers,
no failures) still exits 0. In long-running mode (`-interval` > 0) neither
condition stops the process — it logs and keeps retrying on the next
interval, since a systemd-managed service should ride out a transient
server blip rather than die.

### Certificate pinning

The prober's outbound geolocation requests are TLS-pinned to `ip.pn`,
`free.freeipapi.com`, and `ipinfo.io` — see `geolocatePins()` in
`cmd/egress-prober/main.go` for the current pins, how they were captured, and
how to re-capture them. This is a closed allowlist enforced by the
`providertunnel` package: a tunnel opened with an empty pin set refuses to
open at all, and any https host reached through a tunnel that isn't one of
these three is refused outright.

Each host's entry lists a leaf pin and an intermediate-CA pin, and
`providertunnel`'s pin check accepts a match against **either** — it walks
every certificate in the presented chain (leaf and any intermediates) and
accepts as soon as one matches an allowed pin. That makes the intermediate
entry a real safety net: a routine leaf-certificate rotation (Let's Encrypt
roughly every 90 days) still chains to the same intermediate, so the
intermediate pin keeps matching and probing keeps working with no redeploy.
The tradeoff is that pinning an intermediate trusts that CA, not one
specific certificate, for that host. In practice: if probing for a host
starts failing with a pin-mismatch error, that means the *issuing
intermediate* changed (the CA rotated it, or the host switched CAs
entirely), and the fix is to re-capture and redeploy **both pins** for that
host (see the recipe in `geolocatePins()`'s doc comment).

### Design

This tool geolocates a network provider by routing HTTPS geolocation
lookups *through that provider's own tunnel*, rather than trusting the
provider to self-report a location: the prober host never queries a
geolocation api directly, only through a tunnel pinned to exactly one
provider (see "Certificate pinning" above), so each lookup's response
reflects that provider's actual egress point. Results from the three
independent sources are reconciled into a consensus (see `geolocate/`) and
submitted to the operator's server (see `ingest/`), which can then correct
its own record of that provider's location. There is no separate design
document in the server repo; this README plus the package doc comments in
`geolocate/`, `providertunnel/`, `prober/`, and `ingest/` are the design
reference.
