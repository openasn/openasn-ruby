# frozen_string_literal: true

module OpenASN
  # The verdict precedence ladder. First match wins. This ordering IS the
  # product — change it only with the data repo's DECISIONS.md open next to
  # you, because every line encodes a documented false-positive lesson:
  #
  #    1. invalid input                       -> InvalidIPError (raised in IP.parse)
  #    2. special ranges                      -> :private / :cgnat
  #    3. relay overlays (Tier B: Apple)      -> :relay
  #    4. tor overlays (Tier B)               -> :tor_exit
  #    5. vpn ranges (canonical X4B ∪ Tier B provider lists) -> :vpn
  #    6. ASN flag vpn_provider               -> :vpn
  #    7. ASN flag enterprise_gw ∪ Tier B gateway ranges -> :enterprise_gateway
  #    8. cloud provider ranges (Tier B)      -> :hosting (provider tagged)
  #    9. canonical dc overlay (X4B)          -> :hosting
  #   10. flags bad_asn|hosting_extra|cdn or category==hosting -> :hosting
  #   11. ASN flag mobile_carrier             -> :mobile
  #   12. category isp, role != tier1_transit -> :residential_isp
  #   13. category business                   -> :business
  #   14. category education_research         -> :education
  #   15. category government_admin           -> :government
  #   16. category isp + tier1_transit        -> :unknown (pure-backbone ambiguity)
  #   17. ASN found, no category              -> :unknown
  #   18. no ASN                              -> :unknown (unrouted)
  #
  # Why relay outranks EVERYTHING data-driven: iCloud Private Relay egress
  # lives inside Cloudflare/Akamai space, which the base layer correctly
  # calls hosting — paying iCloud+ customers would classify as datacenter
  # traffic without rule 3. Same defensive logic for enterprise gateways
  # (rule 7 beats the hosting rules: Zscaler ranges are offices, not
  # servers). Rules 12/16: see the data repo's DECISIONS.md D-IMPL-1 —
  # every national telco carries a transit role in upstream data; only
  # pure tier-1 backbone is genuinely ambiguous.
  module Classifier
    module_function

    def classify(snapshot, ip_input)
      family, ip_int = IP.parse(ip_input)
      ip_string = ip_input.is_a?(String) ? ip_input : ip_input.to_s

      # Rule 2 — specials don't need data at all.
      if (special = SpecialRanges.match(ip_int, family))
        return Result.new(ip: ip_string, verdict: special[0], sources: [special[1]])
      end

      layers = snapshot.family(family)

      # The base layer is consulted regardless of the winning rule: even a
      # Tor exit's Result should say which ASN announces it.
      asn, flags = layers.base.find(ip_int)
      flags ||= 0
      category = BinaryFormat.category_name(flags)
      role = BinaryFormat.role_name(flags)

      # Context flags never decide verdicts; they ride along for app logic.
      context = []
      snapshot.overlays_for(family, "flag:cloudflare_range").each do |(_, layer)|
        context << :cloudflare_range if layer.cover?(ip_int)
      end
      snapshot.overlays_for(family, "flag:mixed_high_risk").each do |(_, layer)|
        context << :mixed_high_risk if layer.cover?(ip_int)
      end

      verdict, provider, sources = decide(snapshot, layers, family, ip_int, flags, category, role, asn)

      Result.new(
        ip: ip_string, verdict: verdict, asn: asn,
        as_org: snapshot.org_name(asn), category: category, network_role: role,
        provider: provider, sources: sources, flags: flags,
        context_flags: context, unrouted: asn.nil?
      )
    end

    def decide(snapshot, layers, family, ip_int, flags, category, role, asn) # rubocop:disable Metrics
      # 3 — relay
      if (hit = overlay_hit(snapshot, family, "relay", ip_int))
        return [:relay, hit.provider, [hit.id.to_sym]]
      end

      # 4 — tor
      if (hit = overlay_hit(snapshot, family, "tor_exit", ip_int))
        return [:tor_exit, hit.provider, [hit.id.to_sym]]
      end

      # 5 — vpn ranges. Provider-attributed Tier B lists are consulted
      # BEFORE the anonymous canonical overlay on purpose: when both match
      # (common — X4B covers most VPN hosting space), the verdict is
      # identical but "ProtonVPN" beats provider=nil for explainability.
      if (hit = overlay_hit(snapshot, family, "vpn", ip_int))
        return [:vpn, hit.provider, [hit.id.to_sym]]
      end

      return [:vpn, nil, [:x4b_vpn]] if layers.vpn.cover?(ip_int)

      # 6 — vpn by ASN flag
      return [:vpn, nil, [:asn_vpn_provider]] if flags.anybits?(BinaryFormat::FLAG_VPN_PROVIDER)

      # 7 — enterprise gateway (flag, then Tier B ranges)
      return [:enterprise_gateway, nil, [:asn_enterprise_gw]] if flags.anybits?(BinaryFormat::FLAG_ENTERPRISE_GW)

      if (hit = overlay_hit(snapshot, family, "enterprise_gateway", ip_int))
        return [:enterprise_gateway, hit.provider, [hit.id.to_sym]]
      end

      # 8 — cloud provider ranges (provider attribution is the value-add)
      if (hit = overlay_hit(snapshot, family, "hosting", ip_int))
        return [:hosting, hit.provider, [hit.id.to_sym]]
      end

      # 9 — canonical datacenter overlay
      return [:hosting, nil, [:x4b_dc]] if layers.dc.cover?(ip_int)

      # 10 — hosting by ASN signal
      if flags.anybits?(BinaryFormat::FLAG_BAD_ASN | BinaryFormat::FLAG_HOSTING_EXTRA | BinaryFormat::FLAG_CDN) ||
         category == "hosting"
        return [:hosting, nil, hosting_sources(flags, category)]
      end

      # 11 — mobile
      return [:mobile, nil, [:asn_mobile_carrier]] if flags.anybits?(BinaryFormat::FLAG_MOBILE)

      # 12–17 — category ladder
      if category == "isp"
        return role == "tier1_transit" ? [:unknown, nil, [:isp_transit_ambiguous]] : [:residential_isp, nil, [:asn_category]]
      end
      return [:business, nil, [:asn_category]]   if category == "business"
      return [:education, nil, [:asn_category]]  if category == "education_research"
      return [:government, nil, [:asn_category]] if category == "government_admin"
      return [:unknown, nil, [:asn_no_category]] if asn

      # 18 — unrouted
      [:unknown, nil, [:unrouted]]
    end

    def overlay_hit(snapshot, family, maps_to, ip_int)
      snapshot.overlays_for(family, maps_to).each do |(entry, layer)|
        return entry if layer.cover?(ip_int)
      end
      nil
    end

    def hosting_sources(flags, category)
      sources = []
      sources << :asn_bad_asn       if flags.anybits?(BinaryFormat::FLAG_BAD_ASN)
      sources << :asn_hosting_extra if flags.anybits?(BinaryFormat::FLAG_HOSTING_EXTRA)
      sources << :asn_cdn           if flags.anybits?(BinaryFormat::FLAG_CDN)
      sources << :asn_category      if category == "hosting"
      sources
    end
  end
end
