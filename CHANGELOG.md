# Changelog

## [0.2.0] - 2026-07-06

### Added

- 34 new Tier B VPN provider sources (fetch-manifest entries + parsers),
  organized into config groups:
  - `vpn_providers` (enabled by default — provider-published exact-IP
    endpoints): Mullvad, IVPN, Private Internet Access, AirVPN, Windscribe,
    PrivadoVPN, RiseupVPN, WLVPN, WorldVPN, OVPN, and Anonine — joining
    ProtonVPN from 0.1.0.
  - `vpn_heavy` (opt-in): NordVPN (~35 MB API response; deliberate opt-in).
  - `vpn_dns` (opt-in — provider-published hostnames resolved via local DNS):
    Surfshark, IPVanish, PrivateVPN, PureVPN, TorGuard, FastestVPN, VPNSecure,
    TunnelBear, StrongVPN, VyprVPN, Giganews, SlickVPN, AzireVPN, VPN.ac, and
    Trust.Zone.
  - `public_relays` (opt-in — volunteer-run, high-churn): VPN Gate, VPNBook,
    and FreeVPN.us.
- New parser machinery, all stdlib and dependency-free: HTML table/status
  parsers, a bounded ZIP reader for `.ovpn` archive sources (64 MB inflate
  cap), threaded DNS hostname resolution with an injectable
  `Configuration.dns_resolver` hook, and `HttpClient#post_form` for provider
  endpoints that require form POSTs (redirects preserve method and headers).

### Changed

- Overlay lookups are served from a per-family index precomputed once per
  snapshot — measurably faster lookups with many overlays enabled (the old
  per-lookup scan was allocation-heavy past ~8 overlays).

### Fixed

- The default dataset URL is now the tag-addressed
  `releases/download/latest/…` form, which stays pinned to the rolling
  release no matter which release holds GitHub's "Latest" badge. The
  superficially equivalent `releases/latest/download/…` form resolves via the
  badge and briefly served a frozen weekly snapshot on 2026-07-05. Applied
  everywhere the URL appears (default config, install generator template,
  docs) and pinned by a regression test. See the data repo's DECISIONS.md
  D-REL-1.

## [0.1.0] - 2026-07-05

- Initial release: offline IP origin classification (verdict-first API),
  bundled data seed, nightly refresh from OpenASN releases, Tier B
  fetch-manifest executor (Apple Private Relay, Tor exits, cloud provider
  ranges, provider-attributed VPN overlays), Rack middleware, Rails install
  generator.

[0.2.0]: https://github.com/openasn/openasn-ruby/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/openasn/openasn-ruby/releases/tag/v0.1.0
