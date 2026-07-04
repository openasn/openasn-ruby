# frozen_string_literal: true

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

    attr_reader :ip, :verdict, :asn, :as_org, :category, :network_role,
                :provider, :sources, :flags, :context_flags

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
      @context_flags = context_flags.freeze
      @unrouted = unrouted
      freeze
    end

    def infrastructure? = INFRASTRUCTURE_VERDICTS.include?(verdict)
    def likely_human?   = LIKELY_HUMAN_VERDICTS.include?(verdict)

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
