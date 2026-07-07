# Changelog

## [0.3.1] - 2026-07-07

### Fixed

- `rails generate openasn:install` now inserts `OpenASN::UpdateJob` under an
  existing `production:` entry in `config/recurring.yml` instead of appending
  a duplicate top-level key that can make YAML parsers drop existing jobs.
- README scheduling guidance now calls out that manual update jobs should run
  after the 03:17 UTC data build, using UTC to avoid daylight-saving drift.
- Removed the top-level `rexml/document` require from the WLVPN Tier B parser
  so production Ruby 3.4 bundles that exclude the `rexml` bundled gem can boot
  and precompile assets without adding app-side dependencies.

## [0.3.0] - 2026-07-07

Ergonomics release, driven by dogfooding the analytics/enrichment use case
(surfacing IP origin in admin panels) in a production Rails app.

### Added

- `Result#label` — the verdict as a short human-readable string
  ("Residential ISP", "Hosting / datacenter", "Privacy relay") for admin
  tables, tooltips, and log lines. One label per verdict, same append-only
  contract as the enum.
- `Result#flag_names` — the ASN-level flag bitfield decoded to symbols
  (`[:bad_asn, :vpn_provider]`), plus `Result#flag?(name)` and
  `Result#bad_asn?` sugar. No more bit arithmetic to answer "is this ASN in
  bad-asn-list?".
- `OpenASN.try_lookup(ip)` — nil-safe lookup: returns `nil` on nil/blank/
  unparseable input instead of raising. The right call site for views and
  analytics over historical data, where a garbage IP is data, not an
  exception.
- `Result#to_h` now includes `flag_names` (append-only key addition; the
  raw `flags` integer was useless in a log line).

### Changed

- README reframed analytics-first: enriching admin panels/audit trails is
  the primary documented use case; acting on the signal (step-up
  verification, rate limits) is the optional later step.

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

[0.3.1]: https://github.com/openasn/openasn-ruby/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/openasn/openasn-ruby/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/openasn/openasn-ruby/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/openasn/openasn-ruby/releases/tag/v0.1.0
