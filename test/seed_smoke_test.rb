# frozen_string_literal: true

require "test_helper"

# The bundled seed must be genuinely useful on its own (no network, no
# Tier B): ASN lookup, categories, hosting/vpn/dc verdicts, special ranges.
# This is the same spot panel the data pipeline enforces (spotchecks.yml in
# the data repo), minus rows that need Tier B overlays. If a seed refresh
# breaks one of these, the seed is bad — do not ship it.
class SeedSmokeTest < Minitest::Test
  PANEL = {
    "8.8.8.8" => :hosting,           # Google
    "16.16.10.10" => :hosting,       # AWS
    "104.16.0.1" => :hosting,        # Cloudflare (via category, not X4B)
    "146.70.107.100" => :vpn,        # M247
    "185.220.101.5" => :vpn,         # Tor-heavy range (:tor_exit only with Tier B)
    "95.121.10.10" => :residential_isp,  # Telefónica ES
    "95.90.200.10" => :residential_isp,  # Vodafone DE
    "99.49.80.100" => :residential_isp,  # AT&T (tier1 consumer fix)
    "100.191.100.50" => :mobile,     # T-Mobile USA
    "164.137.224.100" => :enterprise_gateway, # Zscaler
    "38.217.219.100" => :unknown,    # Cogent tier1 backbone — honest unknown
    "81.9.5.10" => :business,        # Vimpelcom
    "10.1.2.3" => :private,
    "100.64.0.1" => :cgnat,
    "100.127.255.255" => :cgnat,
    "127.0.0.1" => :private,
    "2001:4860:4860::8888" => :hosting, # Google DNS v6
    "fd00::1" => :private,
    "::1" => :private
  }.freeze

  def test_bundled_seed_passes_the_spot_panel
    failures = PANEL.filter_map do |ip, expected|
      got = OpenASN.lookup(ip)
      "#{ip}: expected #{expected}, got #{got.verdict} (#{got.sources.inspect})" if got.verdict != expected
    end
    assert_empty failures, failures.join("\n")
  end

  def test_seed_exposes_asn_and_category_details
    r = OpenASN.lookup("8.8.8.8")
    assert_equal 15_169, r.asn
    assert_equal "hosting", r.category
    assert r.infrastructure?
    # as_org comes from the orgs sidecar, which is deliberately NOT bundled
    # (size budget) — nil until the first data refresh downloads it.
    assert_nil r.as_org
  end

  def test_seed_ipv6_backbone_works
    r = OpenASN.lookup("2001:4860:4860::8888")
    assert_equal 15_169, r.asn
  end

  def test_dataset_info_shape
    info = OpenASN.dataset_info
    assert_equal :seed, info[:origin]
    assert_equal :packed, info[:memory_mode]
    assert info[:build_id]
    assert_operator info[:records][:base_ipv4], :>, 300_000
    assert_operator info[:records][:vpn_ipv4], :>, 1_000
    assert_kind_of Hash, info[:tier_b_status]
  end
end
