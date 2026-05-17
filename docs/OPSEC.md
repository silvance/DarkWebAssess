# OPSEC notes

This tool talks to clearweb aggregator pages (Ahmia, etc.) and, with the
Tor sidecar enabled, to onion-hosted aggregators. The aggregator operators
log the requests they receive. If you don't want your residential or
corporate IP appearing in those logs, you need a network layer between
the tool and the public internet.

## Recommended layout

```
+---------------+    +---------------+    +-------------+
|  Streamlit /  | -> |  WireGuard    | -> |  Internet   |
|  CLI tool     |    |  tunnel (UDP) |    |  / Tor      |
+---------------+    +---------------+    +-------------+
                            |
                            v
                    +---------------+
                    | OS firewall   |
                    | "kill switch" |
                    | drops every-  |
                    | thing not in  |
                    | the tunnel    |
                    +---------------+
```

Three properties that matter:

1. **Always-on**: WireGuard starts at boot, before any user session.
2. **Fail-closed**: if the tunnel drops, no packets leave the box via the
   physical NIC. This is a firewall rule, not a WireGuard feature.
3. **DNS locked to the tunnel**: queries go through the VPN's resolver
   (or 1.1.1.1 over the tunnel), never through your ISP.

Do NOT have the tool start or stop WireGuard. Routing is an OS-level
concern; the tool just *verifies* it before fetching.

## Setting up WireGuard (Windows)

1. Install WireGuard for Windows: <https://www.wireguard.com/install/>.
2. Drop your provider-supplied `.conf` file into WireGuard, click
   Activate.
3. Set it to autostart on boot:
   ```powershell
   wireguard.exe /installtunnelservice "C:\Program Files\WireGuard\Data\Configurations\YourTunnel.conf.dpapi"
   ```
4. Kill switch via Windows Firewall. Replace `10.0.0.0/8` with your
   tunnel's allowed range:
   ```powershell
   # Block all outbound on the physical interface (replace name).
   New-NetFirewallRule -DisplayName "DWA-KillSwitch" -Direction Outbound `
     -Action Block -InterfaceAlias "Ethernet" -Profile Any
   # Allow only WireGuard handshake (UDP/51820) and traffic over the tunnel.
   New-NetFirewallRule -DisplayName "DWA-AllowWG" -Direction Outbound `
     -Action Allow -Protocol UDP -RemotePort 51820
   ```
   (WireGuard for Windows also has a built-in `Block untunneled traffic
   (kill-switch)` toggle — flip it on in the tunnel settings; it's much
   simpler than custom firewall rules.)

## Setting up WireGuard (Linux)

```bash
sudo apt install wireguard
sudo cp your-vpn.conf /etc/wireguard/wg0.conf
sudo systemctl enable --now wg-quick@wg0
```

Kill switch with `nftables` or `iptables`:

```bash
# Block all outbound except WG handshake (UDP/51820) and the tunnel itself.
sudo iptables -P OUTPUT DROP
sudo iptables -A OUTPUT -o wg0 -j ACCEPT
sudo iptables -A OUTPUT -o lo -j ACCEPT
sudo iptables -A OUTPUT -p udp --dport 51820 -j ACCEPT
```

## Verifying with the tool

After setting up WireGuard, find your VPN provider's egress IP ranges
(they publish them) and set:

```bash
export EXPECTED_EGRESS_PREFIXES="185.156.176.0/20,194.110.0.0/16"
export STRICT_EGRESS=1
```

Then:

```bash
dwa network-check
# [network-check] egress IP: 185.156.180.42
# [network-check] allowlist:  185.156.176.0/20, 194.110.0.0/16
# [network-check] result:     in-prefix:185.156.176.0/20
```

With `STRICT_EGRESS=1`, the `collect`, `scheduler`, and `discover run`
commands all run the same check at startup and refuse to proceed if the
egress IP is outside the allowlist (or if the lookup itself fails). This
is the "even if WG dropped, the tool won't leak" property.

## Stronger options

- **Per-process network namespace (Linux only).** Run the tool in a
  netns whose only interface is `wg0`. If the tunnel is down, the
  namespace has no network at all — zero-leak by construction.
  ```bash
  sudo ip netns add dwa
  sudo ip link set wg0 netns dwa
  sudo ip -n dwa link set wg0 up
  sudo ip netns exec dwa python -m app.main collect
  ```
- **Windows Firewall per-executable rule.** Restrict
  `mini-threat-intel.exe` so it can ONLY reach the VPN subnet
  (e.g. `10.0.0.0/8`). Survives WG-down because the deny applies
  regardless.
- **Whonix or Tails for active investigations.** Don't mix personal and
  operational. If you're doing real CI work, the dark-web side should
  live in a separate VM (or separate hardware) with the network stack
  locked to Tor.

## Threat model assumptions

- Your VPN provider is in the trust boundary. They see that you connect
  to Tor and to clearweb aggregators.
- Your ISP / corporate network sees only WireGuard packets to a single
  VPN endpoint. They cannot tell whether you're browsing Reddit or
  hitting Ahmia.
- Tor entry nodes see the VPN IP, never yours.
- Aggregator operators see the VPN IP and a generic Firefox UA. They
  cannot link the request to you without help from the VPN provider.

## What this tool does NOT do

- Manage WireGuard itself (start/stop, install, configure).
- Block traffic when the tunnel is down (that's the firewall's job).
- Force traffic through the VPN (that's the routing table's job).
- Spoof, hide, or alter packets in any way.

It is a *verifier*, not a *router*. The actual routing has to be set up
correctly at the OS layer.
