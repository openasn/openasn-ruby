# OpenASN — offline IP origin intelligence.
# Docs: https://github.com/openasn/openasn-ruby
#
# Everything below shows the DEFAULT — uncomment only what you change.

OpenASN.configure do |config|
  # Where downloaded data lives. Default: Rails.root/storage/openasn.
  # Containerized? Point this at a persistent volume, or each boot starts
  # from the bundled seed and re-downloads (~15MB) on first refresh.
  # config.data_dir = Rails.root.join("storage", "openasn")

  # :packed → ~11MB RSS, ~20µs per lookup (right for almost everyone)
  # :arrays → ~8x the memory, ~2µs per lookup (lookup-heavy pipelines)
  # config.memory_mode = :packed

  # Allow automatic refreshes (UpdateJob + boot staleness check).
  # config.auto_update = true

  # Self-host or pin the data source if you need to:
  # config.release_url = "https://github.com/openasn/openasn/releases/latest/download/"
  # config.pin_version = "2026-07-04"   # a dated release tag, for reproducible builds

  # Tier B overlays — fetched by YOUR server from the original authorities
  # (Apple, Tor Project, AWS…), per the project's fetch-manifest. Defaults:
  # config.tier_b = {
  #   apple_relay: true,     # iCloud Private Relay → :relay (real users! never block)
  #   tor: true,             # Tor Project exits    → :tor_exit
  #   clouds: true,          # AWS/GCP/Azure/OCI/DO/Linode/Vultr → :hosting (+provider)
  #   vpn_providers: true,   # first-party VPN lists (ProtonVPN) → :vpn (+provider)
  #   zscaler: false,        # extra :enterprise_gateway ranges (ASN flags already cover most)
  #   nazgul_mixed: false    # broad "high-risk hosting" flag — NOT a VPN signal; opt-in
  # }

  # config.logger = Rails.logger
end

# Optional: classify every request once and read it anywhere downstream as
# request.env["openasn.result"]. (Costs ~20µs/request.)
#
# ⚠️  Behind a proxy/CDN? Make sure Rails' trusted proxies are set up so
# remote_ip is the real client — otherwise you'll classify your own load
# balancer on every request. See "Trusted proxies" in the README.
#
# Rails.application.config.middleware.use OpenASN::Middleware

# Optional: eager-load the dataset at boot (first lookup otherwise pays
# ~50-200ms of lazy loading once per process):
#
# Rails.application.config.after_initialize { OpenASN.eager_load! }

# ── Shadow mode (START HERE — measure before you act) ──────────────────────
# Log verdicts on your critical flows for a couple of weeks:
#
#   result = OpenASN.lookup(request.remote_ip)
#   Rails.logger.info(openasn: result.to_h.merge(flow: "signup"))
#
# Then, and only then, act — prefer step-up verification over hard blocks:
#
#   # Rack::Attack example (config/initializers/rack_attack.rb):
#   # Rack::Attack.blocklist("openasn: infrastructure on signup") do |req|
#   #   req.post? && req.path == "/signup" && OpenASN.lookup(req.ip).infrastructure?
#   # end
#
# infrastructure? is true only for :hosting/:vpn/:tor_exit (high-confidence
# classes). :relay, :cgnat and :mobile are REAL PEOPLE — never hard-block.
