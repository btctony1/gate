# gate

VPN Gate residential node system: Cloudflare check worker + GitHub Actions generator + Pages subscription.

- `vpngate.py` — fetches the official VPN Gate list, checks TCP servers through the check worker, publishes live nodes to `docs/`.
- Entry node (edgetunnel on Cloudflare) is configured in the client; chained configs expect its SOCKS inbound on 127.0.0.1:10808.
