# ADR 0003: Egress proxy against DNS rebinding

- **Status:** Proposed. The owner accepts or rejects it; nothing is implemented
  before that (P3.3).
- **Date:** 2026-10-21
- **Decided by:** project owner

## Context

The capture browser visits hostile pages. A page must not be able to make it reach
private addresses: the operator's network (a router, a NAS), the Docker host, or the
cloud metadata service. Today one guard enforces that, inside the browser process
(`capture/browser.py`): every request and WebSocket goes through a route handler
that resolves the hostname with `getaddrinfo` and refuses private, loopback,
link-local and reserved addresses.

That guard has a gap: it resolves the name, then Chromium resolves it **again** on
its own to connect. The two answers need not agree. A site whose DNS server answers
a public address to the first lookup and `192.168.1.1` to the second, with a time to
live of zero, gets past the check: DNS rebinding. The guard also caches each answer
for the whole job, which makes the first answer the only one checked.

What is actually exposed today:

| Where the capture runs | Reachable through rebinding | Already limited by |
|---|---|---|
| AWS instance | the VPC resolver (`10.0.0.2`), the Docker host through the bridge gateway | Instance metadata needs IMDSv2 tokens with a hop limit of 1 (`infra/instance.tf`), so a container cannot obtain one: the credentials are out of reach. Nothing else listens in the VPC. Docker publishes no port beyond loopback, but any host service listening on all interfaces is reachable through the gateway |
| A home machine (P2.3, second vantage point) | the home network: router admin pages, NAS, printers, other devices | Nothing beyond the browser guard |

So the risk is low on the instance and real at home, where P2.3 suggests capturing.

## Decision (proposed)

Put a forward proxy between the browser and the internet, and give the capture
container no other way out:

1. **A proxy container** on two networks: an internal one shared with the capture
   container, and the outside one. For each connection it resolves the hostname
   once, refuses it if any answer is private, and connects to the address it
   checked. There is no second lookup for an attacker to answer differently.
2. **The capture network becomes `internal: true`**: Docker gives it no route out.
   The only thing the browser can reach is the proxy. This also stops traffic the
   current guard never sees: WebRTC and QUIC (UDP) have no route at all.
3. **Chromium gets `--proxy-server`**: it sends hostnames to the proxy instead of
   resolving them, so it does no DNS of its own.
4. **The proxy is Stripe's Smokescreen**, built from a pinned release in its own
   image. It exists for exactly this (an egress proxy that blocks internal address
   ranges, at Stripe), and logs every connection it allows or refuses.
5. **The browser guard stays.** It still refuses literal private addresses and
   other schemes before a request leaves, and gives clear `blocked` results. Two
   layers, one of which no longer depends on DNS agreeing with itself.

To verify before implementation, not assumed here: Smokescreen's current release
and its pinned commit, its default denied ranges (they must cover RFC 1918,
loopback, link-local including `169.254.169.254`, CGNAT, IPv6 unique-local and
link-local), and how it reports a refusal to the browser.

## Alternatives rejected

**A firewall on the host** (`DOCKER-USER` iptables rules dropping traffic from a
fixed capture subnet to private ranges). The kernel would enforce it on the real
address of every packet, so rebinding could not get past it either, and it is ten
lines. Rejected as the main fix because it only exists on a Linux host configured
for it: Docker Desktop on the home machine, the exposed case, would not have it.
Worth adding later on the instance as defence in depth.

**Writing our own proxy** (an asyncio CONNECT proxy, about 200 lines). Fully
explainable, testable offline. Rejected: HTTP proxy parsing (absolute-form
requests, keep-alive across hosts, CONNECT edge cases) is where such code goes
wrong, and a maintained tool built for this purpose exists.

**Pinning DNS inside Chromium** (`--host-resolver-rules` mapping the visited host to
the checked address). Covers only the host we visit, not the scripts, images and
redirects a page pulls from other hosts.

**Keeping things as they are.** Acceptable for the instance alone, thanks to
IMDSv2. Not for captures from a home network.

## Consequences

- **Statuses change shape.** With a proxy, Chromium reports a failed or refused
  connection as a proxy error (`ERR_TUNNEL_CONNECTION_FAILED`, an HTTP 503 from the
  proxy) rather than `ERR_NAME_NOT_RESOLVED`. `classify_error` must map these, or
  dead domains will be counted as errors instead of `dns_error`, and the "DNS failed,
  skip the HTTP retry" shortcut stops working. Capture statistics before and after
  the change are not directly comparable; STATUS records the date.
- **The browser guard can no longer resolve names** (the internal network has no
  outside DNS). It treats an unresolvable name as "let the browser report it", so
  it keeps working, but its DNS check becomes inert and the proxy does that job.
- **One more container** on the instance: a Go binary, tens of MB of memory, inside
  the ADR 0002 budget. The memory test of ADR 0002 should be rerun.
- **A connection log**: every host the browser reached or was refused, which is
  useful evidence of what a kit tried to load.
- **Tests:** the proxy refuses a private address, a rebinding name and a literal
  IP, using a local DNS stub and no real network call; compose keeps the capture
  network internal; the browser starts with the proxy setting.
- **Capture container protections are unchanged or stronger:** the same user,
  dropped capabilities, read-only root, seccomp profile (P3.2) and limits.
