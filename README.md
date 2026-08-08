# Obelisk

**The universal VPN client for OpenWrt.
One client, two cores, your whole subscription.**

One subscription can carry VLESS over REALITY, Trojan over gRPC, Shadowsocks and
Hysteria2 all at once. No single core handles all of that well. Obelisk reads the
subscription, works out which core can actually carry each server, and runs both
— sing-box in front owning the tunnel, Xray behind it for the protocols only it
supports. You get one list of servers and one switch.

*Русская версия: [README.ru.md](README.ru.md)*

![Obelisk dashboard](docs/dashboard.png)

<!-- Replace docs/dashboard.png with a screenshot of your own Overview page. -->

---

## Why this exists

Running a VPN on the router rather than on every device is the right shape for a
household: the TV, the console and the guest's phone all get the same routing,
and nobody installs anything. On OpenWrt the options for that are thin, and the
ones that exist tend to pick one core and stop there.

Obelisk is built for the router specifically:

- **Both cores, chosen per server.** Not "supports Xray *or* sing-box" — both,
  running together, picked per node from what the protocol actually needs.
- **The cores stay stock.** They are separate executables, downloaded from their
  own releases and never patched. Updating a core is replacing a file, not
  rebuilding Obelisk.
- **One static binary.** Pure Go, `CGO_ENABLED=0`, the web interface embedded.
  Deploying is copying one file. There is no build step, no `node_modules`, and
  no runtime to install.
- **It gets out of the way.** Obelisk owns exactly one nftables table and never
  touches anyone else's. It detects zapret and coexists with it — see below,
  because that turned out to be harder than it sounds.

## What it does

**Subscriptions.** Share links, base64, Clash YAML, sing-box JSON and Xray JSON.
Panels serve different formats to different clients, so the User-Agent is
selectable per subscription and the format actually received is shown — which is
usually the whole explanation for a subscription that looks empty.

**Split tunnelling, in three shapes.** One list, and a switch that says how to
read it: *proxy the list*, *bypass the list*, or *everything through the tunnel*.
Paste anything into the box — a URL from the address bar, `*.wildcard`, an IP, a
subnet, a keyword — and Obelisk tells you how it understood each line.

**Provider routing, merged with yours.** Many subscriptions ship their own list
of what should bypass the tunnel. Obelisk imports it and applies it *beneath*
your rules, so nothing you wrote can be overridden and nothing you wrote is lost
when you change provider.

**Capture modes.** TUN, TPROXY, REDIRECT, or proxy-only, switchable at runtime.

**Split DNS that is actually split.** Names that will be reached through the
tunnel are resolved through it; everything else is resolved directly. Building
that from the routing rules rather than declaring it is the difference between
the claim and the behaviour.

**Reachability, as two questions.** "Is there internet" is asked of hosts that
are never blocked. "Is the tunnel carrying anything" is asked of hosts that are
blocked, *through the core's own proxy* — reaching one is the only proof the
traffic really left through the tunnel. A single "connected" light cannot tell
those apart, and that is exactly the failure it hides.

**Live traffic, by route and by device.** The throughput chart is stacked by
where the bytes went — through the tunnel or around it. The connections panel
groups by which machine on the LAN is responsible, with names from the router's
DHCP leases.

**A CLI that is not an afterthought.** Everything the browser does, the command
line does, against the same daemon.

## Install

### Docker (recommended)

```bash
git clone https://github.com/HilistonGit/Obelisk.git
cd obelisk
docker compose up -d
docker compose logs | grep token      # the access token for the web interface
```

Then open `http://<router>:24080`.

Host networking is not optional for the transparent modes: Obelisk has to put its
interface and its rules on the router's own network stack.

### Binary

```bash
make release                       # every OpenWrt architecture into dist/
scp dist/obelisk-linux-arm64 root@router:/usr/bin/obelisk
ssh root@router 'obelisk core install all && obelisk daemon'
```

Cross-compiles to `amd64`, `arm64`, `armv7`, `armv6`, `mipsle`, `mips` and
`riscv64`. The cores are fetched at runtime for the architecture and libc the
router actually has — musl and glibc builds are not interchangeable, and the
wrong one fails with a "file not found" that names a file which is right there.

## Use

```bash
obelisk parse   <subscription>     # what is in it
obelisk plan    <subscription>     # which core takes each server, and why
obelisk route add "https://www.youtube.com/watch?v=..." "*.googlevideo.com" 142.250.0.0/15
obelisk route test rutracker.net   # what would happen to it
obelisk core update all            # update the cores in place, with rollback
obelisk daemon                     # web interface, API, cores
```

## Living with a DPI bypass

If you run [zapret](https://github.com/bol-van/zapret) or similar, the two
interfere in a way neither reports. In TUN mode every connection the LAN makes is
terminated by the core and re-opened from the router; zapret's injected packets
are locally generated, and a tunnel with `auto_route` captures exactly those. The
fakes go into the tunnel instead of to the provider, the DPI never sees them, and
transfers to hosts on zapret's list stall part-way through.

Measured on a live router, the same 10 MB download:

| | download |
|---|---|
| tunnel off, zapret on | 10 000 000 B @ 8.7 MB/s |
| tunnel on, zapret on, no accommodation | **21 102 B @ 844 B/s** |
| tunnel on, zapret **off** | 10 000 000 B @ 9.2 MB/s |
| tunnel on, zapret on, `share` mode | 10 000 000 B @ 7.6 MB/s |

Obelisk detects zapret and adds one routing rule that lets its packets out past
the tunnel. Nothing of zapret's configuration is touched — its strategies come
from upstream and change often. Both tools then do their job: zapret holds the
direct path, the tunnel takes what zapret cannot.

## How it fits together

```
        LAN ──► tun / tproxy / redirect
                     │
                sing-box  ── owns inbounds, routing, DNS
                     │
        ┌────────────┴────────────┐
     direct                    proxy
                                 │
                    ┌────────────┴────────────┐
            native outbound            SOCKS bridge ──► Xray
       (VLESS, Trojan, SS, Hysteria2)              (XHTTP, and anything
                                                    only Xray carries)
```

`docs/ARCHITECTURE.md` goes through the reasoning in depth — the topology, the
routing engine, the firewall marks, and a list of things that were wrong on real
hardware and how they were found. *(That document is in Russian.)*

## Building

```bash
make check      # gofmt, go vet, go test, and a smoke test of the web interface
make build      # one binary for this machine
make release    # every architecture
```

The interface is plain ES modules and CSS with no build step, embedded with
`go:embed`. `web/smoke.mjs` runs it under Node against a stub DOM and drives
every screen, which is what catches a handler a refactor left dangling — in a
browser that failure is a blank page and one console line.

## Status

Working and in daily use on a Raspberry Pi 4 running OpenWrt 24.10. Expect rough
edges; issues and pull requests are welcome.

## Licence

MIT — see [LICENSE](LICENSE). The cores are separate programs under their own
licences and are not modified or linked against.
