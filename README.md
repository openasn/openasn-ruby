# 🛰️ `openasn` — offline IP origin intelligence for Ruby

[![Gem Version](https://badge.fury.io/rb/openasn.svg)](https://badge.fury.io/rb/openasn) [![Build Status](https://github.com/openasn/openasn-ruby/workflows/Tests/badge.svg)](https://github.com/openasn/openasn-ruby/actions)

> [!TIP]
> **🚀 Ship your next Rails app 10x faster!** I've built **[RailsFast](https://railsfast.com/?ref=openasn)**, a production-ready Rails boilerplate template that comes with everything you need to launch a software business in days, not weeks. Go [check it out](https://railsfast.com/?ref=openasn)!

`openasn` tells you what kind of network an IP address is *really* coming from — **residential ISP, mobile carrier, hosting/datacenter, VPN, Tor exit, iCloud Private Relay, enterprise gateway, business, education, government, CGNAT** — entirely offline, in ~20 microseconds, with **zero API calls, zero per-lookup cost, and zero runtime dependencies**.

```ruby
result = OpenASN.lookup(request.remote_ip)

result.verdict          # => :residential_isp
result.label            # => "Residential ISP" — human-readable, for admin UIs & logs
result.infrastructure?  # => false  (true only for :hosting / :vpn / :tor_exit)
result.likely_human?    # => true   (:residential_isp, :mobile, :relay, :cgnat, :enterprise_gateway)
result.asn              # => 3352
result.as_org           # => "TELEFONICA DE ESPANA S.A.U."
result.sources          # => [:asn_category]  — every verdict is auditable
```

It answers, at zero marginal cost, the question every product eventually asks: **where do my signups, logins, and checkouts actually come from?** Enrich your admin panel, analytics, and audit trails with network origin — and if you ever decide to *act* on the signal, the same verdict drives step-up verification or rate limits. It's the data that costs $79–$200/month from commercial IP-intelligence APIs, as free, open, auditable data — compiled nightly from legally clean sources by the [OpenASN data project](https://github.com/openasn/openasn), with a data seed bundled right in the gem so it works on first boot, offline.

> [!IMPORTANT]
> **What this is NOT.** A clean or `:residential_isp` verdict is **absence of evidence, not proof of innocence**. Residential proxies — malicious traffic exiting through real home IPs — are structurally hard to detect offline, and OpenASN does not claim to detect them. `:vpn`, `:hosting`, and `:tor_exit` are high-confidence; treat everything else as a signal, not a sentence. **Never hard-block `:relay`, `:cgnat`, or `:mobile` — those are real people.** OpenASN tells you what the network *is*; it is not a fraud engine, and a verdict is a fact to weigh, never a sentence to execute.

## How it works

```
┌────────────────────────────┐    nightly     ┌──────────────────────────────┐
│ openasn/openasn (data)     │ ─────────────▶ │ your server                  │
│ 560k+ IP ranges, all ASNs, │  GitHub        │  gem seed → daily UpdateJob  │
│ VPN/DC overlays, curated   │  Releases      │  + Tier B overlays fetched   │
│ corrections (CC0)          │  (free CDN)    │  from original authorities:  │
└────────────────────────────┘                │  Apple relay list, Tor exits,│
                                              │  AWS/GCP/Azure/OCI ranges…   │
   lookups: local binary search, ~20µs,       └──────────────────────────────┘
   no user IP ever leaves your server
```

- **Bundled seed**: the gem ships with a full snapshot — works offline from the first boot, forever.
- **Nightly refresh**: `OpenASN::UpdateJob` pulls updated artifacts (SHA-256 verified, atomically swapped — readers never block, never see partial data).
- **Tier B overlays**: fast-moving lists (Tor exits, Apple Private Relay, cloud ranges, exact VPN provider server lists) are fetched by *your* server directly from the original authorities — never proxied through anyone.
- **Data never flows through gem releases.** The gem versions on code; the data has its own nightly release channel.

## Installation

```ruby
# Gemfile
gem "openasn"
```

Then:

```bash
bundle install
rails generate openasn:install
```

The generator creates `config/initializers/openasn.rb` (documented defaults) and, if you're on Solid Queue, schedules the daily `OpenASN::UpdateJob` in `config/recurring.yml`. **No migrations, no database** — data lives in `storage/openasn/` as memory-mapped-style packed files.

If you wire the job yourself, schedule it after the OpenASN data build
publishes at **03:17 UTC**. The generator uses `every day at 4:12am UTC` on
purpose; local time zones with daylight saving can drift before the UTC build
and fetch yesterday's release.

Not on Rails? `OpenASN.lookup` works anywhere Ruby ≥ 3.1 runs; schedule `OpenASN.update!` daily with cron/whenever.

## The API

### Lookup

```ruby
r = OpenASN.lookup("146.70.107.100")   # aliases: OpenASN.check, OpenASN.[]
# Never nil. Raises OpenASN::InvalidIPError (an ArgumentError) on garbage input.

r = OpenASN.try_lookup(user.signup_ip) # nil-safe variant: nil/blank/garbage in,
                                       # nil out — right for views and analytics
                                       # over historical data

r.verdict         # one of: :residential_isp :mobile :business :hosting :vpn
                  #         :tor_exit :relay :enterprise_gateway :education
                  #         :government :cgnat :private :unknown
r.label           # "VPN" — the verdict as a short human-readable string
r.infrastructure? # :hosting | :vpn | :tor_exit — the honest, high-confidence boolean
r.likely_human?   # :residential_isp | :mobile | :relay | :cgnat | :enterprise_gateway
r.vpn? r.hosting? r.tor? r.relay? r.mobile? r.private? r.cgnat?

r.asn             # 9009
r.as_org          # "M247 Europe SRL"  (nil until the first data refresh downloads org names)
r.category        # "hosting"          (raw upstream category)
r.network_role    # "major_transit"    (raw upstream routing role)
r.provider        # "aws" | "ProtonVPN" | "iCloud Private Relay" | nil (overlay attribution)
r.sources         # [:x4b_vpn] — which data layer decided; every verdict is auditable
r.flag_names      # [:vpn_provider, :bad_asn] — ASN-level signals, decoded to names
r.bad_asn?        # ASN is in brianhama/bad-asn-list (infrastructure signal, not an accusation)
r.flag?(:cdn)     # named check for any flag in r.flag_names' vocabulary
r.context_flags   # [:cloudflare_range] — context that never decides verdicts
r.unrouted?       # true when no ASN announces this IP
r.flags           # raw u16 for power users (see the data project's FORMAT.md)
r.to_h            # everything, stable keys — built for shadow-mode logging
```

Note the deliberate asymmetry: `:business`, `:education`, `:government`, and `:unknown` are **neither** `infrastructure?` **nor** `likely_human?` — that's your call, not the gem's. There is intentionally no `suspicious?` — that's a policy word, and your app owns policy.

### The mental model: verdict, category, flags, sources

OpenASN returns one object, but its fields answer different questions:

| Field | What it answers | How to use it |
|---|---|---|
| `verdict` | "What should my app consider this IP?" | Primary policy input. Switch on this. |
| `infrastructure?` | "Is this high-confidence non-eyeball infrastructure?" | Safe shorthand for `:hosting`, `:vpn`, `:tor_exit`. |
| `likely_human?` | "Is blocking this IP likely to hit real people?" | True for residential/mobile/relay/CGNAT/enterprise gateways. |
| `category` | Raw ASN category from upstream data (`"isp"`, `"hosting"`, `"business"`, ...) | Context for logs and analyst UI. Do not treat it as the verdict. |
| `network_role` | Raw routing role (`"access_provider"`, `"midsize_transit"`, `"tier1_transit"`, ...) | Explains why some ISP ASNs stay human while pure backbones stay unknown. |
| `sources` | Which rule/data layer decided the verdict | Best debugging field. Log it. |
| `provider` | Provider attribution from an exact overlay hit (`"aws"`, `"azure"`, `"ProtonVPN"`, ...) | Display/log it when present; nil is normal. |
| `context_flags` | Extra context that never decides the verdict | Useful for policy experiments; do not block solely on it. |
| `flag_names` | ASN-level signals, decoded (`:bad_asn`, `:vpn_provider`, `:mobile_carrier`, `:enterprise_gw`, `:cdn`, `:hosting_extra`) | Display/log them; `bad_asn?` and `flag?(:name)` are the sugar. |
| `flags` | Packed low-level artifact bits | Wire detail; prefer `flag_names` in app code. |

Common examples:

- A DIGI Spain home IP is usually `category: "isp"` and `verdict: :residential_isp`. That is expected: `category` describes the ASN; `verdict` is OpenASN's safer application-level label.
- An Amazon IP may be `category: "hosting"`, `sources: [:x4b_dc]`, and with Tier B enabled `provider: "aws"`. The verdict remains `:hosting`; Tier B only improves attribution.
- `bad_asn?` is not an accusation and not a verdict. It means the ASN appears in `brianhama/bad-asn-list`, a curated MIT-licensed hosting/cloud/colo ASN list. When that signal decides classification, `sources` includes `:asn_bad_asn`.
- `:residential_isp` means "known eyeball ISP, no stronger infrastructure signal found." It does **not** mean "safe user."

### Verdict cheat sheet

| Verdict | Meaning | Confidence | Advice |
|---|---|---|---|
| `:hosting` | datacenter/cloud/colo | high | fine to challenge on sensitive flows |
| `:vpn` | known VPN egress | high | challenge > block (privacy users are customers too) |
| `:tor_exit` | Tor exit node | high (with Tier B fresh) | your policy |
| `:relay` | iCloud Private Relay | high | **treat like CGNAT — real paying humans** (Apple says the same) |
| `:enterprise_gateway` | Zscaler-style corporate egress | high | humans at work; never block |
| `:residential_isp` | eyeball ISP | *absence of evidence* | trust but verify |
| `:mobile` | cellular carrier | high | one IP = hundreds of humans (CGNAT); no per-IP rate-limits |
| `:cgnat` / `:private` | RFC 6598 / RFC 1918 space | certain | check your proxy config if you see these on public traffic |
| `:business` / `:education` / `:government` | org category from ASN data | medium | your policy |
| `:unknown` | genuinely ambiguous (e.g. tier-1 backbone, uncategorized ASN) | honest | design for it — `unknown` is a feature, not a bug |

### API stability contract

Your `case result.verdict` statements and shadow-log parsers are API surface. The rules, from 0.1.0 onward:

- **The verdict enum is append-only.** Existing verdicts are never removed, renamed, or silently redefined (a meaning change would be a major version). New verdicts may be *added* in a minor version, announced loudly in the CHANGELOG — so give exhaustive `case` statements an `else` branch (treat unknown-to-you verdicts as you treat `:unknown`).
- **Verdicts are code, not data: a data refresh can never emit a verdict your gem version doesn't know.** The nightly artifacts carry ranges and flag bits; the mapping to verdicts is compiled into the client. Data updates are always safe to auto-apply.
- **`Result#to_h` keys are append-only** — shadow-mode logs you write today stay parseable tomorrow.
- **`sources` and `context_flags` symbols are informational**: new ones appear as data sources evolve. Log them, display them, never exhaustively match on them.
- **Config keys are additive**; artifact bytes are governed by the data project's [FORMAT.md](https://github.com/openasn/openasn/blob/main/FORMAT.md) (any layout change bumps `format_version`, and readers reject unknown versions rather than guess).

### Configuration (all optional)

```ruby
OpenASN.configure do |config|
  config.data_dir     = Rails.root.join("storage", "openasn") # default; use a persistent volume in containers
  config.memory_mode  = :packed   # :packed ~11MB data resident, ~15µs/lookup · :arrays faster, more RAM
  config.auto_update  = true
  config.release_url  = "https://github.com/openasn/openasn/releases/download/latest/" # self-hostable; tag-addressed on purpose (badge-immune, see data repo DECISIONS.md D-REL-1)
  config.pin_version  = nil       # e.g. "2026-07-04" to pin a dated data release
  config.tier_b       = { apple_relay: true, tor: true, clouds: true,
                          vpn_providers: true, vpn_heavy: false,
                          vpn_dns: false, public_relays: false, zscaler: false,
                          nazgul_mixed: false }
  config.logger       = Rails.logger
end
```

`vpn_providers: true` enables small/stable exact-IP provider lists such as ProtonVPN, Mullvad, IVPN, Private Internet Access, AirVPN, Windscribe, PrivadoVPN, RiseupVPN, WLVPN, WorldVPN, OVPN, and Anonine. WLVPN is backend infrastructure powered by IPVanish and used by white-label resellers such as FastVPN/Namecheap/Spaceship; OpenASN labels the exact source as `provider: "WLVPN"` rather than guessing the reseller. WorldVPN, OVPN, and Anonine publish exact IPs in first-party server/status tables or JSON endpoints, so they do not need DNS expansion. `vpn_heavy: true` opts into large or historically fragile provider APIs such as NordVPN. `vpn_dns: true` opts into provider-published hostnames resolved by your server's DNS at update time, covering sources such as Surfshark, IPVanish, PrivateVPN, PureVPN, TorGuard, FastestVPN, VPNSecure, TunnelBear, StrongVPN, VyprVPN, Giganews VyprVPN, SlickVPN, AzireVPN, VPN.AC, and Trust.Zone; this is useful but intentionally off by default because DNS answers can vary by resolver/vantage. `public_relays: true` opts into volunteer/free relay networks such as VPN Gate, VPNBook, and FreeVPN.us, which can label residential-looking IPs as `:vpn` while they are actively advertised as relays. FreeVPN.us intentionally includes only OpenVPN/WireGuard/PPTP rows; SSH Tunnel and V2Ray rows are excluded from the VPN overlay.

### Updates

```ruby
OpenASN.update!        # refresh now → :updated | :tier_b_only | :unchanged | :locked
OpenASN.dataset_info   # build id, origin (:seed/:data_dir), record counts, per-source Tier B status
OpenASN.eager_load!    # load at boot instead of first lookup (~50–200ms once per process)
```

Updates are atomic end to end: SHA-256 verified against the release manifest → written to temp files → `rename(2)` into place → in-memory snapshot swapped in a single assignment. Concurrent lookups never block and never see partial state; concurrent updaters (multi-worker Puma) coordinate via file lock; sibling processes pick up new data within ~5 minutes via a one-`stat()` freshness probe. Every Tier B source failure keeps last-good data and surfaces in `dataset_info` — a broken upstream can never crash your app or silently blank a signal.

### Rack middleware (optional)

```ruby
# config/initializers/openasn.rb
Rails.application.config.middleware.use OpenASN::Middleware

# anywhere downstream:
request.env["openasn.result"]&.infrastructure?
```

> [!WARNING]
> **The classic integration bug:** behind a proxy/CDN without trusted-proxy configuration, you'll classify your own load balancer on every request (everything comes back `:private` or your host's datacenter). Inside Rails the middleware uses `remote_ip` semantics (honors `config.action_dispatch.trusted_proxies`); make sure the real client IP reaches your app — e.g. with the `cloudflare-rails` gem when behind Cloudflare.

## Recommended rollout: enrich first, act later (maybe never)

Start where the value is certain and the risk is zero: **visibility**. Put the verdict next to every IP your team already looks at. For many apps that's the whole integration — and it's how we dogfood it ourselves.

```ruby
# 1. ENRICH — pure analytics, blocks nothing, breaks nothing:
#    surface origin in your admin panel and audit trails…
OpenASN.try_lookup(user.signup_ip)&.label   # "Residential ISP" / "VPN" / "Hosting / datacenter"

#    …and/or log it on the flows you care about:
class RegistrationsController < ApplicationController
  def create
    Rails.logger.info(openasn: OpenASN.lookup(request.remote_ip).to_h.merge(flow: "signup"))
    # … existing signup logic unchanged
  end
end

# 2. If (and only if) your OWN data says you have an abuse problem worth the
#    friction, act — prefer step-up verification (email confirm, captcha,
#    phone) over hard blocks:
Rack::Attack.blocklist("openasn: infrastructure on signup") do |req|
  req.post? && req.path == "/signup" && OpenASN.lookup(req.ip).infrastructure?
end
```

**Who should NOT rely on this:** banks, crypto exchanges, KYC flows, high-chargeback marketplaces — you need paid behavioral intelligence (MaxMind Anonymous IP/Residential Proxy, IPQS…). OpenASN is your prefilter at most.

## What you can and cannot conclude (honesty section)

**Can:** recognize known infrastructure with high confidence; identify network type; explain every verdict (`sources`); do it all offline with zero latency budget and zero privacy leakage (user IPs never leave your server).

**Cannot:** detect residential proxies (structurally invisible offline — that's why the paid products exist); prove any IP is safe; outrun VPN infrastructure churn beyond nightly + Tier B cadence; promise IPv6 range-overlay parity (v6 VPN signal rides ASN-level data; documented lower confidence).

## Performance

Measured on the bundled real dataset (433k+ IPv4 ranges, 125k+ IPv6, full overlays), pure Ruby, no C extensions:

| mode | lookup | throughput | memory |
|---|---|---|---|
| `:packed` (default) | ~15µs | ~68k/sec/core | ~11MB data |
| `:arrays` | ~9µs | ~108k/sec/core | ~40MB data |

(Apple M-series, canonical-data only; GitHub's shared CI runners measure ~24µs packed / ~12µs arrays. CI asserts a generous 100µs ceiling as a regression tripwire.) Enabling many Tier B overlays adds a few µs per active overlay; with all defaults loaded (~11 overlays) a full lookup is ~35µs on Apple Silicon, still tens of thousands per second per core. Run `rake bench` to measure on your hardware.

## Data provenance & licensing

Every byte in the dataset is traceable: compiled nightly from PDDL/CC0/MIT-licensed sources ([sapics/ip-location-db](https://github.com/sapics/ip-location-db), [ipverse/as-metadata](https://github.com/ipverse/as-metadata), [X4BNet/lists_vpn](https://github.com/X4BNet/lists_vpn), [brianhama/bad-asn-list](https://github.com/brianhama/bad-asn-list)) plus OpenASN's own curated corrections — with upstream license texts SHA-256-pinned in CI and full per-build provenance in `manifest.json`. The dataset is CC0. The details, gates, and the "fetch ≠ redistribute" legal design live in the [data project README](https://github.com/openasn/openasn).

Sibling of [`nondisposable`](https://github.com/rameerez/nondisposable) (disposable-email blocking) and [`trackdown`](https://github.com/rameerez/trackdown) (IP geolocation) — same philosophy: boring, offline, production-grade primitives for Rails apps.

## Development

```bash
bundle install
bundle exec rake test    # full suite, offline (WebMock)
rake bench               # lookup latency on your machine
rake seed:refresh        # pull the latest data release into lib/openasn/data/seed/
```

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/openasn/openasn-ruby. Wrong verdict for an IP? That's usually a *data* issue — check `result.sources` and open it against [openasn/openasn](https://github.com/openasn/openasn) (the override files are one sourced line per PR).

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).
