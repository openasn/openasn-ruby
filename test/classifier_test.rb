# frozen_string_literal: true

require "test_helper"

# The precedence matrix: one assertion per rule, plus every documented
# rule-conflict (the cases where an IP matches MULTIPLE layers and the
# ladder order is what protects real users).
class ClassifierTest < Minitest::Test
  def setup
    super
    FixtureData.install_all(@test_data_dir)
    configure do |c|
      c.tier_b = { apple_relay: true, tor: true, clouds: true,
                   vpn_providers: true, zscaler: true, nazgul_mixed: true }
    end
  end

  def look(ip) = OpenASN.lookup(ip)

  # --- rule 1: invalid input ------------------------------------------------

  def test_invalid_input_raises_argument_error
    assert_raises(OpenASN::InvalidIPError) { look("not-an-ip") }
    assert_raises(ArgumentError) { look("999.1.2.3") }
    assert_raises(OpenASN::InvalidIPError) { look(42) }
  end

  # --- rule 2: specials -----------------------------------------------------

  def test_special_ranges_beat_everything
    assert_equal :private, look("10.1.2.3").verdict
    assert_equal :cgnat, look("100.64.0.1").verdict
    assert_equal :private, look("127.0.0.1").verdict
    assert_equal :private, look("::1").verdict
    assert_equal :private, look("fd00::1").verdict
  end

  # --- rules 3-4: relay, tor ------------------------------------------------

  def test_relay_wins_over_dc_overlay_and_hosting_category
    # 1.0.30.x is: relay overlay + canonical dc overlay + hosting-category
    # ASN — the iCloud Private Relay situation. Relay MUST win.
    r = look("1.0.30.10")
    assert_equal :relay, r.verdict
    assert_equal "iCloud Private Relay", r.provider
    assert_equal [:apple_private_relay], r.sources
    assert_equal 64_530, r.asn # base attribution still present
  end

  def test_tor_wins_over_vpn_overlay
    r = look("1.0.31.5") # in tor overlay AND canonical vpn overlay
    assert_equal :tor_exit, r.verdict
    assert_equal [:tor_exits], r.sources

    # same /26 but not the tor exit → falls through to vpn
    assert_equal :vpn, look("1.0.31.20").verdict
  end

  def test_tor_works_on_ipv6
    assert_equal :tor_exit, look("2001:db8:4::5").verdict
    assert_equal :residential_isp, look("2001:db8:4::6").verdict
  end

  # --- rule 5: vpn ranges (canonical + provider lists) ------------------------

  def test_canonical_vpn_overlay
    r = look("1.0.20.5")
    assert_equal :vpn, r.verdict
    assert_nil r.provider # canonical X4B ranges are anonymous
    assert_equal [:x4b_vpn], r.sources
    # outside the /25 overlay, same ASN → falls to residential
    assert_equal :residential_isp, look("1.0.20.200").verdict
  end

  def test_vpn_overlay_wins_over_dc_overlay
    # 1.0.21.192/26 is in BOTH vpn and dc overlays → vpn (rule 5 < 9)
    assert_equal :vpn, look("1.0.21.200").verdict
    # dc-only part of the /24 → hosting
    assert_equal :hosting, look("1.0.21.10").verdict
  end

  def test_tier_b_vpn_provider_list_gets_attribution
    r = look("1.0.33.7")
    assert_equal :vpn, r.verdict
    assert_equal "ProtonVPN", r.provider
    assert_equal [:protonvpn], r.sources
  end

  # --- rule 6: vpn by ASN flag (the IPv6 VPN path) ----------------------------

  def test_vpn_provider_flag
    r = look("1.0.8.8")
    assert_equal :vpn, r.verdict
    assert_equal [:asn_vpn_provider], r.sources
  end

  def test_vpn_provider_flag_works_on_ipv6
    r = look("2001:db8:3::1")
    assert_equal :vpn, r.verdict
    assert_equal 64_508, r.asn
    assert_equal "Fixture VPN Provider Ltd", r.as_org
  end

  # --- rule 7: enterprise gateway --------------------------------------------

  def test_enterprise_gateway_flag
    r = look("1.0.10.10")
    assert_equal :enterprise_gateway, r.verdict
    assert_equal [:asn_enterprise_gw], r.sources
  end

  def test_tier_b_gateway_ranges_win_over_hosting_category
    r = look("1.0.34.10") # zscaler range over a hosting-category ASN
    assert_equal :enterprise_gateway, r.verdict
    assert_equal "zscaler", r.provider
  end

  # --- rule 8: cloud ranges beat anonymous dc (provider attribution) ----------

  def test_cloud_overlay_gets_provider_attribution_over_dc
    r = look("1.0.32.10") # aws overlay + canonical dc overlay + hosting cat
    assert_equal :hosting, r.verdict
    assert_equal "aws", r.provider
    assert_equal [:aws], r.sources
  end

  # --- rules 9-10: hosting paths ----------------------------------------------

  def test_hosting_via_category
    r = look("1.0.1.1")
    assert_equal :hosting, r.verdict
    assert_equal [:asn_category], r.sources
    assert_equal "hosting", r.category
    assert_equal "content_network", r.network_role
  end

  def test_hosting_via_bad_asn_flag
    r = look("1.0.7.7")
    assert_equal :hosting, r.verdict
    assert_includes r.sources, :asn_bad_asn
  end

  def test_hosting_via_cdn_flag
    assert_equal :hosting, look("1.0.11.11").verdict
  end

  def test_hosting_via_hosting_extra_flag_without_category
    r = look("1.0.12.12")
    assert_equal :hosting, r.verdict
    assert_includes r.sources, :asn_hosting_extra
  end

  # --- rule 11: mobile ---------------------------------------------------------

  def test_mobile_flag_beats_isp_category
    r = look("1.0.9.9")
    assert_equal :mobile, r.verdict
    assert r.likely_human?
  end

  # --- rules 12-17: category ladder ---------------------------------------------

  def test_residential_isp
    r = look("1.0.0.42")
    assert_equal :residential_isp, r.verdict
    assert_equal 64_500, r.asn
    assert_equal "Fixture Residential ISP", r.as_org
    assert r.likely_human?
    refute r.infrastructure?
  end

  def test_isp_with_major_transit_role_is_still_residential
    # The D-IMPL-1 fix: national telcos carry transit roles.
    assert_equal :residential_isp, look("1.0.14.14").verdict
  end

  def test_isp_with_tier1_transit_is_honest_unknown
    r = look("1.0.5.5")
    assert_equal :unknown, r.verdict
    assert_equal [:isp_transit_ambiguous], r.sources
    # the raw signals stay exposed for apps that want their own policy
    assert_equal "isp", r.category
    assert_equal "tier1_transit", r.network_role
  end

  def test_business_education_government
    assert_equal :business, look("1.0.2.2").verdict
    assert_equal :education, look("1.0.3.3").verdict
    assert_equal :government, look("1.0.4.4").verdict
  end

  def test_known_asn_without_category_is_unknown
    r = look("1.0.6.6")
    assert_equal :unknown, r.verdict
    assert_equal [:asn_no_category], r.sources
    assert_equal 64_506, r.asn
    refute r.unrouted?
  end

  # --- rule 18: unrouted ---------------------------------------------------------

  def test_unrouted_gap
    r = look("1.0.13.13")
    assert_equal :unknown, r.verdict
    assert r.unrouted?
    assert_nil r.asn
    assert_equal [:unrouted], r.sources
  end

  # --- context flags never decide verdicts ------------------------------------------

  def test_cloudflare_range_is_context_not_verdict
    r = look("1.0.35.35") # hosting-category ASN inside cloudflare ranges
    assert_equal :hosting, r.verdict
    assert_includes r.context_flags, :cloudflare_range
  end

  def test_mixed_high_risk_never_flips_a_residential_verdict
    r = look("1.0.36.36") # nazgul list over a residential ISP
    assert_equal :residential_isp, r.verdict
    assert_includes r.context_flags, :mixed_high_risk
  end

  # --- tier B off means overlays are ignored -------------------------------------------

  def test_disabled_tier_b_sources_do_not_classify
    configure do |c|
      c.tier_b = { apple_relay: false, tor: false, clouds: false,
                   vpn_providers: false, zscaler: false, nazgul_mixed: false }
    end
    # without the relay overlay, 1.0.30.x falls to the dc overlay → hosting
    assert_equal :hosting, OpenASN.lookup("1.0.30.10").verdict
  end
end
