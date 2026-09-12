# frozen_string_literal: true

require "logger"
require "tmpdir"

module OpenASN
  class Configuration
    # Where downloaded artifacts + Tier B overlays live. Default:
    # Rails.root/storage/openasn (survives deploys on most setups, and
    # storage/ is gitignored by Rails convention), else Dir.tmpdir/openasn.
    # Heads-up for containerized deploys: put this on a persistent volume
    # or every boot starts from the bundled seed + a fresh download.
    attr_writer :data_dir

    # Measured on the real dataset, full classify (parse + all layers):
    # :packed → ~11MB data resident; ~15µs/lookup on Apple Silicon,
    #           ~24µs on GitHub's shared CI runners (default; right for web apps)
    # :arrays → several× the memory; ~9µs/lookup (~1.6x faster — the raw
    #           range probe is ~2µs, but IP parsing + overlay checks
    #           dominate, so the full-lookup win is smaller than that
    #           suggests). For lookup-heavy batch pipelines.
    attr_reader :memory_mode

    # Whether UpdateJob/boot staleness checks may refresh data automatically.
    attr_accessor :auto_update

    # Rolling-release base URL. Override to self-host artifacts (air-gapped
    # deploys, internal mirrors). Must end with "/".
    attr_writer :release_url

    # Per-source Tier B switches (see fetch-manifest.json in the data repo).
    # Keys are FEATURE names, not source ids — they fan out:
    #   apple_relay    → apple_private_relay        (:relay)
    #   tor            → tor_exits                  (:tor_exit)
    #   clouds         → aws gcp azure oracle digitalocean linode vultr
    #                    + cloudflare_ranges context flag
    #   verified_crawlers → the first-party operator recognition lists
    #                    (Googlebot, GPTBot, ClaudeBot, Applebot, CCBot,
    #                    DuckDuckBot, PerplexityBot + the user-triggered
    #                    fetchers). Small, official, and the whole point of
    #                    provider attribution, so ON by default.
    #   verified_crawlers_extra → the tail: coarse Google infra, shared App
    #                    Engine egress, Bingbot (no retrievable terms quote),
    #                    Amazon's HTML-wrapped and months-stale lists.
    #   clouds_extra   → github_meta atlassian fastly huawei scaleway
    #                    ibm_cloud_classic ovh_web_hosting_clusters
    #                    (platform egress and second-tier clouds; opt-in
    #                    because the ranges either sit inside AWS/Azure
    #                    space the `clouds` group covers or inside ASNs the
    #                    core artifact already labels hosting — what these
    #                    add is range-level precision and provider
    #                    ATTRIBUTION, and api.github.com/meta is
    #                    rate-limited to 60 requests/hour unauthenticated)
    #   vpn_providers  → protonvpn mullvad ivpn pia airvpn windscribe
    #                    privado riseup wlvpn worldvpn ovpn
    #                    anonine
    #                    (exact provider-attributed VPN exit/server IPs)
    #   vpn_heavy      → nordvpn                    (large/fragile provider API)
    #   vpn_dns        → surfshark ipvanish privatevpn purevpn torguard fastestvpn
    #                    tunnelbear strongvpn vyprvpn giganews slickvpn
    #                    azirevpn vpn.ac trust.zone cryptostorm
    #                    (provider hostnames resolved locally; opt-in)
    #   public_relays  → vpngate vpnbook freevpn.us (volunteer/free public VPN relays)
    #   zscaler        → zscaler zscaler_gov        (:enterprise_gateway ranges)
    #   swg_egress     → cisco_sse_geofeed cato_pop_ranges (the other SWG/SASE vendors
    #                    publish egress: one Cisco feed covers both Umbrella and
    #                    Secure Access. Zscaler keeps its own switch for
    #                    backwards compatibility - config keys are append-only.)
    #   nazgul_mixed   → nazgul_mixed               (flag only, never :vpn)
    attr_accessor :tier_b

    # Pin data to a dated release tag (e.g. "v2026.07.05") instead of the
    # rolling latest. For reproducible environments and gradual rollouts.
    attr_accessor :pin_version

    # Reserved for the post-MVP edge companion (a CDN worker that stamps a
    # trusted classification header). No behavior in this version.
    attr_accessor :trusted_header

    attr_writer :logger

    # Reserved for future OpenASN Pro editions. Deliberately inert in the
    # open gem — configuring it does nothing today and never will for the
    # free dataset (see the data repo's open-data contract).
    #
    # Tier C BYOD adapters (bring-your-own MaxMind/IP2Location databases)
    # are post-MVP and deliberately ship NO placeholder keys here: new
    # config keys are additive and non-breaking to introduce later, whereas
    # a placeholder whose shape turns out wrong would force a breaking
    # rename. They'll appear alongside the adapters themselves.
    attr_accessor :api_key

    TIER_B_DEFAULTS = {
      apple_relay: true,
      tor: true,
      clouds: true,
      clouds_extra: false,  # platform egress attribution (GitHub Actions, Atlassian); opt-in
      verified_crawlers: true,        # small official recognition lists; the agent-era answer
      verified_crawlers_extra: false, # coarse, shared-tenant, stale or unquotable lists
      zscaler: false,       # ASN-level enterprise_gateway overrides already cover Zscaler
      swg_egress: false,    # non-Zscaler SWG/SASE vendor egress (Cisco SSE, Cato); opt-in
      vpn_providers: true,
      vpn_heavy: false,     # e.g. NordVPN's ~35MB API response; opt in deliberately
      vpn_dns: false,       # provider-published hostnames resolved by local DNS; opt in deliberately
      public_relays: false, # volunteer relays like VPN Gate; useful, but high-churn
      nazgul_mixed: false   # semantics broader than VPN; opt-in only
    }.freeze

    # Feature switch → fetch-manifest source ids.
    TIER_B_SOURCE_MAP = {
      apple_relay: %w[apple_private_relay],
      tor: %w[tor_exits],
      clouds: %w[aws gcp azure oracle digitalocean linode vultr cloudflare_ranges],
      clouds_extra: %w[github_meta atlassian fastly_ranges huawei_cloud_geofeed
                       scaleway_ranges ibm_cloud_classic ovh_web_hosting_clusters],
      verified_crawlers: %w[google_common_crawlers google_special_crawlers
                            google_user_triggered_fetchers_google google_user_triggered_agents
                            openai_gptbot openai_chatgpt_user openai_searchbot openai_adsbot
                            anthropic_bots applebot commoncrawl_ccbot duckduckbot
                            perplexitybot perplexity_user mistralai_user mistralai_index],
      verified_crawlers_extra: %w[bingbot google_infra google_user_triggered_fetchers_gae
                                  amazonbot amzn_searchbot amzn_user ahrefsbot],
      zscaler: %w[zscaler zscaler_gov],
      swg_egress: %w[cisco_sse_geofeed cato_pop_ranges],
      vpn_providers: %w[protonvpn mullvad_relays ivpn_servers pia_servers airvpn_status windscribe_servers
                        privadovpn riseup_vpn wlvpn_server_list worldvpn_servers ovpn_servers
                        anonine_status],
      vpn_heavy: %w[nordvpn_servers],
      vpn_dns: %w[surfshark_generic surfshark_static surfshark_obfuscated ipvanish_openvpn
                  privatevpn_openvpn purevpn_openvpn torguard_openvpn_tcp torguard_openvpn_udp
                  fastestvpn_tcp fastestvpn_udp tunnelbear_openvpn strongvpn_locations
                  vyprvpn_openvpn giganews_vyprvpn_hosts slickvpn_locations azirevpn_locations
                  vpnac_status trustzone_servers cryptostorm_configs],
      public_relays: %w[vpngate vpnbook_openvpn freevpn_us_servers],
      nazgul_mixed: %w[nazgul_mixed]
    }.freeze

    def initialize
      @data_dir = nil
      @memory_mode = :packed
      @auto_update = true
      @release_url = nil
      @tier_b = TIER_B_DEFAULTS.dup
      @pin_version = nil
      @trusted_header = nil
      @logger = nil
      @api_key = nil
    end

    def data_dir
      @data_dir ||= if defined?(Rails) && Rails.respond_to?(:root) && Rails.root
                      File.join(Rails.root.to_s, "storage", "openasn")
                    else
                      File.join(Dir.tmpdir, "openasn")
                    end
    end

    def memory_mode=(mode)
      raise ArgumentError, "memory_mode must be :packed or :arrays, got #{mode.inspect}" unless %i[packed arrays].include?(mode)

      @memory_mode = mode
    end

    def release_url
      return @release_url if @release_url
      return "https://github.com/openasn/openasn/releases/download/#{pin_version}/" if pin_version

      # Tag-addressed form: the rolling release's TAG is literally "latest",
      # so this path stays pinned to it no matter which release holds
      # GitHub's "Latest" BADGE. The superficially equivalent
      # `releases/latest/download/...` resolves via that badge (whatever
      # release was created last - REST `make_latest` defaults to "true"),
      # and the first weekly dated snapshot stole it once (2026-07-05):
      # default-config clients would have silently fetched up-to-6-day-old
      # data until the next snapshot. Do not "simplify" this back.
      # Refs: https://docs.github.com/en/repositories/releasing-projects-on-github/linking-to-releases
      #       https://docs.github.com/en/rest/releases/releases#create-a-release
      #       data repo DECISIONS.md D-REL-1
      "https://github.com/openasn/openasn/releases/download/latest/"
    end

    def logger
      @logger ||= if defined?(Rails) && Rails.respond_to?(:logger) && Rails.logger
                    Rails.logger
                  else
                    Logger.new($stdout, level: Logger::INFO, progname: "openasn")
                  end
    end

    def enabled_tier_b_source_ids
      tier_b.flat_map { |feature, on| on ? TIER_B_SOURCE_MAP.fetch(feature, []) : [] }
    end

    def user_agent
      "openasn-ruby/#{VERSION} (+https://github.com/openasn/openasn)"
    end
  end
end
