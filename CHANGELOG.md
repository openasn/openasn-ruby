# Changelog

## Unreleased

- Added exact-IP Tier B parsers and configuration groups for Mullvad, IVPN,
  Private Internet Access, AirVPN, Windscribe, PrivadoVPN, RiseupVPN,
  NordVPN (`vpn_heavy` opt-in), and VPN Gate/VPNBook (`public_relays` opt-in).
- Added opt-in DNS-expanded Tier B support (`vpn_dns`) for provider-published
  hostnames such as Surfshark, IPVanish, PrivateVPN, PureVPN, TorGuard,
  FastestVPN, and VPNSecure
  while keeping the gem dependency-free.

## [0.1.0] - 2026-07-05

- Initial release: offline IP origin classification (verdict-first API),
  bundled data seed, nightly refresh from OpenASN releases, Tier B
  fetch-manifest executor (Apple Private Relay, Tor exits, cloud provider
  ranges, provider-attributed VPN overlays), Rack middleware, Rails install
  generator.
