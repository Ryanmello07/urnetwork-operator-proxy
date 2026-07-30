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
  The prober refuses to start unless it has verified it *cannot* reach those
  apis directly (see "Confinement" below).
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

### Confinement (required)

The prober **refuses to start** unless it is confined: at startup it attempts a
direct TCP connection to every geolocation endpoint and exits non-zero if any of
them accepts one.

The confinement itself is supplied by the deployment, not by this process —
under Docker Compose a restricted network, otherwise a systemd unit with

```ini
IPAddressDeny=any
IPAddressAllow=<the operator's api/platform addresses>
```

Both mechanisms are outside this process and neither is portably inspectable, so
the prober tests the *property* instead of the mechanism: if a direct connection
succeeds, the confinement is missing and the prober will not run. Without it, a
probe that fails to tunnel would fall back to the host's own egress and record
**the operator's** location for that provider — and hand the operator's address
to third-party APIs. The addresses tested are derived from
`geolocate.SourceHosts()` **and** `egresshealth.DestinationHosts()`, so there is
no second endpoint list to drift.

**Inability to verify is not evidence of confinement.** The check only reports a
pass when it obtained real evidence, and refuses to start otherwise:

- A host that will not resolve is **not** dialed by name. That dial would be
  re-resolved by the resolver that just failed, so it fails at resolution and
  says nothing about whether the address behind the name is reachable.
- If *some* hosts resolved, those are checked and a `WARNING` names the ones
  that did not — a degraded check never reads like a complete one.
- If *no* host resolved, the prober **exits non-zero**. Under a deny-all
  confinement DNS is blocked too, which used to make every host fall back to a
  name, every dial fail at resolution, and the check log "passed" having tested
  nothing at all — on a host that might have full egress.
- `-confinement-timeout` must be at least **500ms**. Anything shorter expires
  before a connection could have completed, so every address looks blocked
  whether or not it is. (Measured on one unconfined host, in the same second:
  `10ms` → correctly "not confined"; `1ms` → "passed".)

For a jail where DNS legitimately cannot work, supply the addresses instead of
disabling the check: `-confinement-address <ip:port>`, repeated once per probe
endpoint — every geolocation source *and* every egress-health destination (the
error message lists them all; `egresshealth.DestinationHosts()` is the source of
truth for the second half). Resolution is then skipped
and exactly those addresses are dialed. The host part must be an IP literal — a
name there would put the same hole back.

`-skip-confinement-check` disables it. It defaults to **false**, logs two
`WARNING` lines when set, and exists only for an operator running a one-shot
manual probe from a host that is not the operator's. Do not set it in a
deployment.

### Egress health

Provider reliability scoring on the server is **presence-based**:
`reliabilityRunningAggSql` counts reported time blocks and sums
`1.0/valid_client_count`, and never consults delivered bytes. A provider that
stays connected 24/7 while blackholing every byte therefore scores perfectly and
stays selectable — observed on mainnet: one provider accepted 87 KB and returned
0 bytes with `connected = true AND valid = true`.

So each pass also runs an **egress-health check over the same tunnel** the
geolocation probe already opened (never a second one), against nine well-known
destinations in three classes, and logs one line per provider:

```
egress-health: provider=<id> ok=7/9 dns=3/3 cdn=1/3 site=3/3 failed=fastly-jquery,cloudfront-awssdk
```

The classes are what make a partial failure diagnosable. `dns=3/3 cdn=0/3` is a
provider whose egress range is refused by CDNs — the client-visible failure the
geolocation probe cannot see, since geolocation APIs do not care where a request
came from. `ok=0/9` is a blackhole. A flat count could not tell them apart, and
neither could a probe that only ever talks to three geolocation APIs.

Whether the site-class destinations actually discriminate against datacenter
ranges is **not yet validated in the field**: from one datacenter host, both
`amazon` and `reddit` answered normally. That is the first thing the field data
should settle.

- **Nothing is submitted and there is no server endpoint yet.** Storage and the
  "healthy enough to select" verdict are separate work; shipping a verdict
  before the signal has been watched in the field is how a probe starts
  de-listing working providers.
- Destinations are spread across **different operators within each class**, so a
  provider that whitelists one vendor cannot pass a class.
- Each check is a small GET with the body read capped at 4 KiB, so a full run
  costs at most 36 KiB of body — under 1% of one 5 MiB active bandwidth probe.
  A full run against a completely unresponsive provider costs at most one extra
  `-probe-timeout` of wall clock per provider (the whole run shares that one
  budget across three concurrent rounds), so a blackholing provider costs about
  2× `-probe-timeout` in total rather than 4×.
- The health destinations are reached **unpinned** but under ordinary WebPKI
  verification. Pinning nine leaves that rotate on nine schedules would turn
  every routine certificate rotation into a failure indistinguishable from the
  provider blackholing the destination. The geolocation sources stay pinned.
- A run is skipped, and logged as skipped, when the probe has no budget left: a
  run on an expired deadline would fail every destination and read as a
  blackhole.

`egresshealth.DestinationHosts()` is the one place the destination hosts are
written down — the confinement check and `-confinement-address` guidance both
derive from it.

### Which providers get probed

When the server implements `GET /network/provider-egress-due`, it chooses: those
whose stored egress location has gone stale, those never probed, and those not
attempted within its backoff, oldest first. That schedule lives in the database,
so it survives a prober restart instead of re-probing the whole population after
one. `-due-limit` (default 100, server-clamped to 500) sizes the batch;
`-due-url` overrides the derived endpoint.

The prober reports **every attempt** back to
`POST /network/provider-egress-attempt`, success or failure, with a short failure
class (`tunnel_failed`, `no_consensus`, `locate_failed`, `not_confident`,
`submit_failed`). This is load-bearing, not telemetry: the server defers a
provider from the due queue when a probe was recently *attempted*, and a
provider that can never be probed successfully never gets a location row — so
without the report it sorts to the head of the queue on every poll forever and
starves every healthy provider, silently, because the endpoint keeps returning a
full plausible batch.

If the due endpoint returns **404** the server has not deployed it, and the
prober falls back to enumerating providers itself (below) with the `-cache-ttl`
in-memory window applied, exactly as before. A **401** does *not* fall back: that
is a wrong `-operator-secret`, and degrading quietly would produce a
full-looking pass whose every submission the same secret rejects.

The enumeration fallback is broad and stable: it fetches every location that
currently has at least one provider from the operator's server, then asks for
the providers at each of those locations and unions the results. This is
deliberate — asking for only the server's own "best available" guess would
enumerate exactly the providers the server's geo database *already* believes are
in a given place, which is the inverse of what a location-correcting probe needs
to cover.

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
