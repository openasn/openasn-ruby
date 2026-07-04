# frozen_string_literal: true

require "ipaddr"
require "json"

# Builds synthetic OASN/OORG artifacts + Tier B overlays for tests.
#
# This is a deliberately INDEPENDENT implementation of the artifact writer
# (the production writer lives in the data repo's pipeline): if the gem's
# reader and this writer agree, both match FORMAT.md. Keep it dumb and
# byte-literal.
#
# The fixture universe (all inside 1.0.0.0/16 and 2001:db8::/32) exercises
# every precedence rule and the documented rule conflicts. See
# classifier_test.rb for the expectations table.
module FixtureData
  CAT = { nil => 0, "isp" => 1, "hosting" => 2, "business" => 3,
          "education_research" => 4, "government_admin" => 5 }.freeze
  ROLE = { nil => 0, "tier1_transit" => 1, "major_transit" => 2, "midsize_transit" => 3,
           "access_provider" => 4, "content_network" => 5, "stub" => 6 }.freeze

  module_function

  def flags(category: nil, role: nil, bits: [])
    f = CAT.fetch(category) | (ROLE.fetch(role) << 4)
    bits.each { |b| f |= b }
    f
  end

  def v4(str) = IPAddr.new(str).to_i
  def v6(str) = IPAddr.new(str).to_i

  def range(cidr)
    r = IPAddr.new(cidr).to_range
    [r.first.to_i, r.last.to_i]
  end

  B = OpenASN::BinaryFormat

  # rubocop:disable Metrics/MethodLength
  def base_rows_v4
    [
      # [cidr, asn, flags]
      ["1.0.0.0/24",  64_500, flags(category: "isp", role: "access_provider")],
      ["1.0.1.0/24",  64_501, flags(category: "hosting", role: "content_network")],
      ["1.0.2.0/24",  64_502, flags(category: "business", role: "stub")],
      ["1.0.3.0/24",  64_503, flags(category: "education_research")],
      ["1.0.4.0/24",  64_504, flags(category: "government_admin")],
      ["1.0.5.0/24",  64_505, flags(category: "isp", role: "tier1_transit")],
      ["1.0.6.0/24",  64_506, flags], # ASN known, no category
      ["1.0.7.0/24",  64_507, flags(category: "isp", role: "access_provider", bits: [B::FLAG_BAD_ASN])],
      ["1.0.8.0/24",  64_508, flags(category: "hosting", bits: [B::FLAG_VPN_PROVIDER])],
      ["1.0.9.0/24",  64_509, flags(category: "isp", role: "access_provider", bits: [B::FLAG_MOBILE])],
      ["1.0.10.0/24", 64_510, flags(category: "business", bits: [B::FLAG_ENTERPRISE_GW])],
      ["1.0.11.0/24", 64_511, flags(category: "hosting", bits: [B::FLAG_CDN])],
      ["1.0.12.0/24", 64_512, flags(bits: [B::FLAG_HOSTING_EXTRA])],
      # 1.0.13.0/24 deliberately unrouted
      ["1.0.14.0/24", 64_514, flags(category: "isp", role: "major_transit")],
      ["1.0.20.0/24", 64_520, flags(category: "isp", role: "access_provider")],
      ["1.0.21.0/24", 64_521, flags(category: "isp", role: "access_provider")],
      ["1.0.30.0/24", 64_530, flags(category: "hosting")],
      ["1.0.31.0/24", 64_531, flags(category: "isp", role: "access_provider")],
      ["1.0.32.0/24", 64_532, flags(category: "hosting")],
      ["1.0.33.0/24", 64_533, flags(category: "isp", role: "access_provider")],
      ["1.0.34.0/24", 64_534, flags(category: "hosting")],
      ["1.0.35.0/24", 64_535, flags(category: "hosting")],
      ["1.0.36.0/24", 64_536, flags(category: "isp", role: "access_provider")]
    ].map { |(cidr, asn, fl)| [*range(cidr), asn, fl] }
  end
  # rubocop:enable Metrics/MethodLength

  def base_rows_v6
    [
      ["2001:db8:1::/48", 64_600, flags(category: "isp", role: "access_provider")],
      ["2001:db8:2::/48", 64_601, flags(category: "hosting")],
      ["2001:db8:3::/48", 64_508, flags(category: "hosting", bits: [B::FLAG_VPN_PROVIDER])],
      ["2001:db8:4::/48", 64_602, flags(category: "isp", role: "access_provider")]
    ].map { |(cidr, asn, fl)| [*range(cidr), asn, fl] }
  end

  def vpn_rows_v4
    [range("1.0.20.0/25"), range("1.0.21.192/26"), range("1.0.31.0/26")]
  end

  def dc_rows_v4
    [range("1.0.21.0/24"), range("1.0.30.0/24"), range("1.0.32.0/24")]
  end

  BUILD_TS = 1_751_600_000 # fixed for determinism

  def write_artifact(path, family:, base:, vpn: [], dc: [], relay: [])
    asz = family == :ipv4 ? 4 : 16
    pack_addr = lambda do |int|
      family == :ipv4 ? [int].pack("N") : [int >> 64, int & 0xFFFF_FFFF_FFFF_FFFF].pack("Q>Q>")
    end

    out = +"OASN".b
    out << [0x01, family == :ipv4 ? 0x04 : 0x06, 0].pack("CCn")
    out << [BUILD_TS].pack("Q>")
    out << [base.length, vpn.length, dc.length, relay.length].pack("NNNN")
    base.each { |(s, e, asn, fl)| out << pack_addr.call(s) << pack_addr.call(e) << [asn, fl].pack("Nn") }
    [vpn, dc, relay].each { |layer| layer.each { |(s, e)| out << pack_addr.call(s) << pack_addr.call(e) } }

    raise "fixture writer bug: #{asz}" unless out.bytesize == 32 + base.length * (2 * asz + 6) + (vpn.length + dc.length + relay.length) * 2 * asz

    File.binwrite(path, out)
  end

  ORG_NAMES = {
    64_500 => "Fixture Residential ISP",
    64_501 => "Fixture Hosting Co",
    64_508 => "Fixture VPN Provider Ltd"
  }.freeze

  def write_orgs(path, names = ORG_NAMES)
    sorted = names.sort
    blob = +""
    index = +""
    sorted.each do |(asn, name)|
      index << [asn, blob.bytesize].pack("NN")
      blob << name.b
    end
    out = +"OORG".b
    out << [0x01, 0, 0].pack("CCn")
    out << [sorted.length, blob.bytesize].pack("NN")
    out << index << blob
    File.binwrite(path, out)
  end

  # Install the full fixture universe into a data_dir (canonical artifacts
  # + manifest + orgs), as if the updater had downloaded it.
  def install_canonical(data_dir)
    FileUtils.mkdir_p(data_dir)
    write_artifact(File.join(data_dir, "openasn-ipv4.bin"),
                   family: :ipv4, base: base_rows_v4, vpn: vpn_rows_v4, dc: dc_rows_v4)
    write_artifact(File.join(data_dir, "openasn-ipv6.bin"),
                   family: :ipv6, base: base_rows_v6)
    write_orgs(File.join(data_dir, "openasn-orgs.bin"))
    File.write(File.join(data_dir, "manifest.json"),
               JSON.generate({ format_version: 1, edition: "core",
                               build_id: Time.at(BUILD_TS).utc.iso8601 }))
  end

  # Tier B overlays, as if the executor had fetched them.
  def install_tier_b(data_dir)
    store = OpenASN::OverlayStore.new(data_dir)
    store.write("apple_private_relay", maps_to: "relay", provider: "iCloud Private Relay",
                ranges_by_family: { ipv4: [range("1.0.30.0/24")], ipv6: [] })
    store.write("tor_exits", maps_to: "tor_exit", provider: "Tor",
                ranges_by_family: { ipv4: [[v4("1.0.31.5"), v4("1.0.31.5")]],
                                    ipv6: [[v6("2001:db8:4::5"), v6("2001:db8:4::5")]] })
    store.write("aws", maps_to: "hosting", provider: "aws",
                ranges_by_family: { ipv4: [range("1.0.32.0/24")], ipv6: [] })
    store.write("protonvpn", maps_to: "vpn", provider: "ProtonVPN",
                ranges_by_family: { ipv4: [[v4("1.0.33.7"), v4("1.0.33.7")]], ipv6: [] })
    store.write("zscaler", maps_to: "enterprise_gateway", provider: "zscaler",
                ranges_by_family: { ipv4: [range("1.0.34.0/24")], ipv6: [] })
    store.write("cloudflare_ranges", maps_to: "flag:cloudflare_range", provider: "cloudflare",
                ranges_by_family: { ipv4: [range("1.0.35.0/24")], ipv6: [] })
    store.write("nazgul_mixed", maps_to: "flag:mixed_high_risk", provider: "nazgul",
                ranges_by_family: { ipv4: [range("1.0.36.0/24")], ipv6: [] })
  end

  def install_all(data_dir)
    install_canonical(data_dir)
    install_tier_b(data_dir)
  end
end
