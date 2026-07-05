# Changelog

## Unreleased

- Added exact-IP Tier B parsers and configuration groups for Mullvad, IVPN,
  Private Internet Access, AirVPN, Windscribe, NordVPN (`vpn_heavy` opt-in),
  and VPN Gate (`public_relays` opt-in).

## [0.1.0] - 2026-07-05

- Initial release: offline IP origin classification (verdict-first API),
  bundled data seed, nightly refresh from OpenASN releases, Tier B
  fetch-manifest executor (Apple Private Relay, Tor exits, cloud provider
  ranges, provider-attributed VPN overlays), Rack middleware, Rails install
  generator.
