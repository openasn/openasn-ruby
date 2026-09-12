# Changelog

## [Unreleased]

The agent-web release: OpenASN can now answer "this hosting IP is Googlebot"
without growing the verdict enum.

### Added

- **Verified crawler / fetcher attribution.** A `fetch-manifest.json` source
  may declare an optional `role`, and `Result` gains `#crawler` (the operator
  id, e.g. `"googlebot"`, `"chatgpt-user"`), `#crawler_role`,
  `#verified_crawler?` and `#verified_fetcher?`, plus a matching context flag.
  The verdict is untouched — a crawler egress genuinely IS a datacenter, and
  `Result::VERDICTS` remains closed and append-only. What was missing was
  attribution, so allowing Googlebot while throttling anonymous cloud traffic
  is now a one-line policy decision.

  `verified_crawler` and `verified_fetcher` are deliberately separate.
  ChatGPT-User, Perplexity-User and Google's user-triggered fetchers run
  because a PERSON asked for the page and is waiting, and they do not follow
  all robots.txt directives. Reporting them as well-behaved automation would
  invite apps to throttle a human — the exact false positive this library
  exists to avoid.

  Attribution is read from a separate role index, NOT from the verdict
  ladder, and that is load-bearing: measured 2026-09-05, 27 of 28 Bingbot
  prefixes and 100% of OpenAI's crawler prefixes sit inside Microsoft's
  published Azure ranges, and 23 of 317 Googlebot prefixes sit inside GCP's
  cloud.json. If attribution came from the ladder, the cloud overlays would
  silently swallow the entire agent web.

- **20 verified crawler / fetcher sources**, on by default where the list is
  small, official and unambiguous: Googlebot, Google special-case crawlers,
  Google user-triggered fetchers and Google-Agent, OpenAI GPTBot /
  ChatGPT-User / OAI-SearchBot / OAI-AdsBot, Anthropic's combined
  ClaudeBot feed, Applebot, Common Crawl CCBot, DuckDuckBot, PerplexityBot
  and Perplexity-User. Opt-in `verified_crawlers_extra` carries Bingbot,
  Google's coarse `goog.json`, shared App Engine egress, and Amazon's three
  HTML-wrapped lists.

- **Three cloud/platform sources**: `github_meta` (2101 v4 + 648 v6 — GitHub
  Actions egress is the best available answer to "is this a CI runner?"),
  `atlassian`, and `zscaler_gov`, plus new feature switches `clouds_extra`,
  `verified_crawlers` and `verified_crawlers_extra`.

- **Three documentation-as-data clouds** in opt-in `clouds_extra`:
  `scaleway_ranges` (11 v4 + 1 v6), `ibm_cloud_classic` (60 v4) and
  `ovh_web_hosting_clusters` (259 v4 + 66 v6). None of these three ever built
  an ip-ranges endpoint; the authoritative list is a docs page, and all three
  now serve that page as raw markdown from their own domain. The OVH recipe's
  prize is the 24 cluster NAT gateways: every PHP script on an OVH shared
  host egresses from one of them, so a request from `91.134.248.230` is
  server-side automation by construction.

  The IBM parser is the most defensive in the gem, and deliberately so: 509
  of the 759 CIDRs on that page are RFC1918 back-end space. Ingesting the
  document whole would label every home and office LAN on earth as IBM
  hosting. It reads three allowlisted sections and applies an RFC1918 guard
  on top, so a renamed heading degrades to "too few rows" (keep-stale)
  instead of to a catastrophe. The Red Hat and Windows sections are excluded
  because they list endpoints an IBM CUSTOMER must reach — Red Hat and
  Microsoft WSUS — which are not IBM address space.

- **SWG/SASE egress beyond Zscaler**, in a new opt-in `swg_egress` switch:
  `cisco_sse_geofeed` (86 v4 + 65 v6) and `cato_pop_ranges` (40 v4). One
  Cisco feed covers both Umbrella and Cisco Secure Access. `zscaler` keeps
  its own switch — config keys are append-only.

- **`cryptostorm_configs`** in opt-in `vpn_dns` (138 first-party hostnames,
  no new parser — `ovpn_zip_remote_hosts` reads it unchanged).

- **Parsers**: `crawler_ipranges_json` (Google's envelope, copied verbatim by
  Bing, OpenAI, Anthropic, Apple, Perplexity, DuckDuckGo and Common Crawl, so
  a new crawler feed is now a manifest-only change), `amazon_bot_html_json`,
  `github_meta_json`, `fastly_public_ip_list_json`,
  `atlassian_ipranges_json`, `json_string_array`,
  `scaleway_network_mdx`, `ibm_cloud_ip_ranges_markdown`,
  `ovh_web_hosting_cluster_md`, `cato_pop_html`, `ovpn_client_entry_json`,
  and `geofeed_csv_no_widen` —
  RFC 8805 again, but refusing to WIDEN a row. Cisco publishes 142 single
  egress addresses with a bogus /32 mask; handing those to IPAddr silently
  claims 2^96 addresses from a pinhole, so a row whose address has bits set
  below its stated prefix length becomes a host route instead.

- Context flags are now derived from whichever `flag:*` overlays a snapshot
  holds rather than two hardcoded names, so a new flag source in
  fetch-manifest.json works on gems that predate it.

- A bundled-manifest consistency test class: the seed `fetch-manifest.json`
  and `TIER_B_SOURCE_MAP` are two halves of one contract, and nothing linked
  them before. A source could ship and never be fetched because no feature
  switch named its id — invisible at runtime, since the executor just skips.

### Changed

- `Result#to_h` gains `crawler`, `verified_crawler`, `crawler_role` and
  `verified_fetcher`, appended at the END (the to_h append-only contract).
- `slickvpn_locations` parser rewritten for SlickVPN's site redesign: server
  addresses now come from each card's `data-host` copy button.
- `windscribe_servers` is `enabled_default` again. It was demoted on
  2026-09-05 when every Windscribe path answered 403 with a Cloudflare
  challenge; on 2026-09-12 a plain identifying User-Agent gets 200 and 395 v4
  ranges from two independent checks. The demotion reasoning still stands for
  next time: OpenASN does not defeat bot challenges, Tier B runs on the end
  user's network so a block seen from here may not exist there, and keep-stale
  means an overlay fetched earlier keeps classifying.
- `ovpn_status_servers` (32 URLs, one per datacenter) is replaced by
  `ovpn_servers`, OVPN's client bootstrap API — the same 96 exact IPs and 34
  merged ranges in ONE request. A 32x reduction in traffic aimed at a
  provider's own infrastructure, for free.

### Removed

- `vpnsecure_locations` source (the parser stays registered for clients pinned
  to an older manifest). `/vpn-locations/` 404s and `/locations` is now
  marketing copy with zero server hostnames — the list is gone, not moved.

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
