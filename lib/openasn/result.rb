# frozen_string_literal: true

require_relative "binary_format"

module OpenASN
  # The answer to "where is this IP really coming from?". Immutable.
  #
  # Verdict-first design: `verdict` is the closed enum; the predicates are
  # sugar. There is deliberately NO `suspicious?` — that's a policy word,
  # and drawing that line belongs to your application, not this gem.
  #
  # STABILITY CONTRACT (README "API stability contract" is the canonical
  # text; keep in sync): VERDICTS is append-only — never remove, rename,
  # or redefine an entry; additions land in minor versions with a loud
  # CHANGELOG note. Verdicts are compiled code, never data: a data refresh
  # cannot introduce one. to_h keys are append-only. The same contract
  # binds every future client (openasn-js, …) — the enum is the project's
  # cross-language API, defined in the data repo's DECISIONS.md.
  class Result
    VERDICTS = %i[
      residential_isp mobile business hosting vpn tor_exit relay
      enterprise_gateway education government cgnat private unknown
    ].freeze

    # High-confidence "this is infrastructure, not an eyeball connection".
    INFRASTRUCTURE_VERDICTS = %i[hosting vpn tor_exit].freeze

    # "Very likely a human being on the other end" — including the classes
    # people wrongly block: relay users are paying iCloud+ customers,
    # CGNAT/mobile IPs are hundreds of people each, enterprise gateways are
    # entire offices. Note the deliberate asymmetry: business/education/
    # government/unknown are NEITHER infrastructure nor likely_human — your
    # app decides those.
    LIKELY_HUMAN_VERDICTS = %i[residential_isp mobile relay cgnat enterprise_gateway].freeze

    # Short human-readable names for every verdict — what you'd print in an
    # admin table or a log line a human reads. Deliberately neutral wording
    # (no "suspicious", no "risky"): the label states what the network IS;
    # what to do about it is your app's policy. Keys follow the VERDICTS
    # append-only contract.
    LABELS = {
      residential_isp: "Residential ISP",
      mobile: "Mobile carrier",
      business: "Business",
      hosting: "Hosting / datacenter",
      vpn: "VPN",
      tor_exit: "Tor exit",
      relay: "Privacy relay",
      enterprise_gateway: "Corporate gateway",
      education: "University / research",
      government: "Government",
      cgnat: "Carrier NAT",
      private: "Private IP",
      unknown: "Unknown"
    }.freeze

    attr_reader :ip, :verdict, :asn, :as_org, :category, :network_role,
                :provider, :sources, :flags, :context_flags, :flag_names

    def initialize(ip:, verdict:, asn: nil, as_org: nil, category: nil,
                   network_role: nil, provider: nil, sources: [], flags: 0,
                   context_flags: [], unrouted: false)
      @ip = ip
      @verdict = verdict
      @asn = asn
      @as_org = as_org
      @category = category
      @network_role = network_role
      @provider = provider
      @sources = sources.freeze
      @flags = flags
      # The raw u16 is a wire detail; apps want names. Decoded once here so
      # nobody downstream needs BinaryFormat bit knowledge.
      @flag_names = BinaryFormat.flag_names(flags).freeze
      @context_flags = context_flags.freeze
      @unrouted = unrouted
      freeze
    end

    # The verdict as a short human-readable string ("Residential ISP",
    # "Hosting / datacenter") — for admin tables, tooltips, log lines.
    def label = LABELS.fetch(verdict)

    def infrastructure? = INFRASTRUCTURE_VERDICTS.include?(verdict)
    def likely_human?   = LIKELY_HUMAN_VERDICTS.include?(verdict)

    # Named ASN-level flag check: flag?(:bad_asn), flag?(:cdn), … (the full
    # vocabulary is BinaryFormat::FLAG_NAMES.values / the README table).
    def flag?(name) = flag_names.include?(name)

    # The ASN appears in brianhama/bad-asn-list — a curated catalog of
    # hosting/cloud/colo ASNs. An infrastructure signal worth an admin's
    # glance, NOT a verdict override and NOT a claim of abuse.
    def bad_asn? = flag?(:bad_asn)

    def vpn?     = verdict == :vpn
    def hosting? = verdict == :hosting
    def tor?     = verdict == :tor_exit
    def relay?   = verdict == :relay
    def mobile?  = verdict == :mobile
    def private? = verdict == :private
    def cgnat?   = verdict == :cgnat

    # True when no ASN announces this IP (unallocated/unrouted space).
    def unrouted? = @unrouted

    # Everything, for logging and shadow mode. Stable keys — CarHey-style
    # shadow analyses depend on this shape staying append-only.
    # (flag_names added in 0.3.0: the raw bitfield is useless in a log line.)
    def to_h
      {
        ip: ip,
        verdict: verdict,
        infrastructure: infrastructure?,
        likely_human: likely_human?,
        asn: asn,
        as_org: as_org,
        category: category,
        network_role: network_role,
        provider: provider,
        sources: sources,
        flags: flags,
        flag_names: flag_names,
        context_flags: context_flags,
        unrouted: unrouted?
      }
    end

    def inspect
      "#<OpenASN::Result #{ip} verdict=#{verdict}#{asn ? " AS#{asn}" : ''}#{as_org ? " (#{as_org})" : ''} sources=#{sources.inspect}>"
    end
    alias to_s inspect
  end
end
