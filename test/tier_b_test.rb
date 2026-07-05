# frozen_string_literal: true

require "test_helper"

class ParsersTest < Minitest::Test
  P = OpenASN::Parsers

  def test_plain_ip_and_cidr_per_line
    body = "# comment\n1.2.3.4\n\n5.6.7.0/24\n"
    assert_equal %w[1.2.3.4 5.6.7.0/24], P.parse("plain_ip_per_line", body)
    assert_equal %w[1.2.3.4 5.6.7.0/24], P.parse("plain_cidr_per_line", body)
  end

  def test_csv_cidr_first_column_apple_shape
    body = "2.16.9.0/24,US,US-CA,,\n2a02:26f7:c8c0::/44,GB,,,\n"
    assert_equal ["2.16.9.0/24", "2a02:26f7:c8c0::/44"], P.parse("csv_cidr_first_column", body)
  end

  def test_geofeed_csv_skips_comments
    body = "# geofeed\n192.0.2.0/24,US,,\n"
    assert_equal ["192.0.2.0/24"], P.parse("geofeed_csv", body)
  end

  def test_aws_json
    body = JSON.generate({ prefixes: [{ ip_prefix: "3.5.140.0/22" }],
                           ipv6_prefixes: [{ ipv6_prefix: "2600:1f14::/35" }] })
    assert_equal ["3.5.140.0/22", "2600:1f14::/35"], P.parse("aws_json", body)
  end

  def test_gcp_json
    body = JSON.generate({ prefixes: [{ ipv4Prefix: "34.0.0.0/15" }, { ipv6Prefix: "2600:1900::/28" }] })
    assert_equal ["34.0.0.0/15", "2600:1900::/28"], P.parse("gcp_json", body)
  end

  def test_azure_servicetags_json
    body = JSON.generate({ values: [{ properties: { addressPrefixes: ["13.64.0.0/16", "2603:1000::/40"] } }] })
    assert_equal ["13.64.0.0/16", "2603:1000::/40"], P.parse("azure_servicetags_json", body)
  end

  def test_oci_json
    body = JSON.generate({ regions: [{ cidrs: [{ cidr: "129.146.0.0/21" }] }] })
    assert_equal ["129.146.0.0/21"], P.parse("oci_json", body)
  end

  def test_zscaler_json_walks_nested_ranges
    body = JSON.generate({ "zscaler.net" => { "continent : EMEA" => { "city : Zurich" => [
      { "range" => "165.225.0.0/17" }, { "range" => "2a03:eec0::/32" }
    ] } } })
    assert_equal ["165.225.0.0/17", "2a03:eec0::/32"], P.parse("zscaler_json", body)
  end

  def test_mullvad_relays_json
    body = JSON.generate([
      { active: true, ipv4_addr_in: "146.70.128.194", ipv6_addr_in: "2a04:27c0::1" },
      { active: false, ipv4_addr_in: "146.70.128.195" }
    ])
    assert_equal ["146.70.128.194", "2a04:27c0::1"], P.parse("mullvad_relays_json", body)
  end

  def test_ivpn_servers_json
    body = JSON.generate({
      wireguard: [{ hosts: [{ host: "37.120.206.53" }] }],
      openvpn: [{ ip_addresses: ["37.120.206.50"] }]
    })
    assert_equal ["37.120.206.53", "37.120.206.50"], P.parse("ivpn_servers_json", body)
  end

  def test_pia_servers_json
    body = JSON.generate({
      regions: [
        { offline: false, servers: { wg: [{ ip: "151.241.119.235" }],
                                     ovpntcp: [{ ip: "151.241.119.240" }] } },
        { offline: true, servers: { wg: [{ ip: "192.0.2.10" }] } }
      ]
    }) + "\n---signature---\n"
    assert_equal ["151.241.119.235", "151.241.119.240"], P.parse("pia_servers_json", body)
  end

  def test_airvpn_status_json
    body = JSON.generate({ servers: [{ ip_v4_in1: "185.156.175.170", ip_v4_in2: "185.156.175.172",
                                       ip_v6_in1: "2001:ac8:28:8::1" }] })
    assert_equal ["185.156.175.170", "185.156.175.172", "2001:ac8:28:8::1"],
                 P.parse("airvpn_status_json", body)
  end

  def test_windscribe_serverlist_json
    body = JSON.generate({ data: [{ status: 1, groups: [{ ping_ip: "198.44.137.19",
                                                          nodes: [{ ip: "198.44.137.43",
                                                                    ip2: "198.44.137.44",
                                                                    ip3: "198.44.137.45" }] }] }] })
    assert_equal ["198.44.137.19", "198.44.137.43", "198.44.137.44", "198.44.137.45"],
                 P.parse("windscribe_serverlist_json", body)
  end

  def test_nordvpn_servers_json
    body = JSON.generate({ servers: [{ status: "online", station: "194.99.105.99", station_ipv6: "",
                                       ips: [{ ip: { ip: "194.99.105.99" } }] },
                                     { status: "offline", station: "192.0.2.55" }] })
    assert_equal ["194.99.105.99"], P.parse("nordvpn_servers_json", body)
  end

  def test_privado_servers_json
    body = JSON.generate({ servers: [{ ip: "91.148.247.156", hostname: "rs.example" },
                                     { hostname: "missing-ip.example" }] })
    assert_equal ["91.148.247.156"], P.parse("privado_servers_json", body)
  end

  def test_leap_eip_service_json
    body = JSON.generate({ gateways: [{ ip_address: "204.13.164.252", host: "vpn01-sea.riseup.net" }] })
    assert_equal ["204.13.164.252"], P.parse("leap_eip_service_json", body)
  end

  def test_surfshark_clusters_json
    body = JSON.generate([{ connectionName: "al-tia.prod.surfshark.com" }])
    assert_equal ["al-tia.prod.surfshark.com"], P.parse("surfshark_clusters_json", body)
  end

  def test_zip_bomb_is_refused_with_bounded_memory
    # ~66MB of zeros deflates to ~64KB; the inflate cap must trip before the
    # payload materializes (keep-stale semantics downstream, never an OOM).
    zeros = "\0".b * (66 * 1024 * 1024)
    deflated = Zlib::Deflate.new(Zlib::DEFAULT_COMPRESSION, -Zlib::MAX_WBITS)
                            .deflate(zeros, Zlib::FINISH)
    crc = Zlib.crc32(zeros)
    name = "bomb.ovpn".b
    local = ["PK\x03\x04".b, 20, 0, 0, 8, 0, crc, deflated.bytesize, zeros.bytesize,
             name.bytesize, 0].pack("a4vvvvvVVVvv") + name + deflated
    central = ["PK\x01\x02".b, 20, 20, 0, 8, 0, 0, crc, deflated.bytesize, zeros.bytesize,
               name.bytesize, 0, 0, 0, 0, 0, 0].pack("a4vvvvvvVVVvvvvvVV") + name
    eocd = ["PK\x05\x06".b, 0, 0, 1, 1, central.bytesize, local.bytesize, 0].pack("a4vvvvVVv")

    error = assert_raises(P::ParseError) { P.parse("ovpn_zip_remote_hosts", local + central + eocd) }
    assert_match(/inflates past/, error.message)
  end

  def test_ovpn_zip_remote_hosts
    zip = stored_zip(
      "one.ovpn" => "client\nremote vpn1.example.com 1194\n",
      "nested/two.ovpn" => "remote 203.0.113.10 443 tcp\n",
      "provider/three.ovpn.txt" => "remote vpn3.example.com 443\n",
      "README.txt" => "remote ignored.example.com 1194\n"
    )
    assert_equal ["vpn1.example.com", "203.0.113.10", "vpn3.example.com"], P.parse("ovpn_zip_remote_hosts", zip)
  end

  def test_vpnbook_html_hosts
    body = '<a href="/freevpn/openvpn">us16.vpnbook.com</a> www.vpnbook.com ca149.vpnbook.com'
    assert_equal ["us16.vpnbook.com", "ca149.vpnbook.com"], P.parse("vpnbook_html_hosts", body)
  end

  def test_html_table_hostnames
    body = "<tr><td>Australia</td><td>Sydney</td><td>au-stream.jumptoserver.com</td></tr>"
    assert_equal ["au-stream.jumptoserver.com"], P.parse("html_table_hostnames", body)
  end

  def test_strongvpn_locations_html
    body = '<a href="http://vpn-sf85.reliablehosting.com/">Speedtest</a> VPN-LO54.RELIABLEHOSTING.COM'
    assert_equal ["vpn-sf85.reliablehosting.com", "vpn-lo54.reliablehosting.com"],
                 P.parse("strongvpn_locations_html", body)
  end

  def test_vpnsecure_locations_html
    body = <<~HTML
      <dt>
        <div class="icon-flag"></div>
        au1
        <span class="status status--up">up</span>
      </dt>
      <dt>
        <div class="icon-flag"></div>
        us4
        <span class="status status--down">down</span>
      </dt>
    HTML
    assert_equal ["au1.isponeder.com"], P.parse("vpnsecure_locations_html", body)
  end

  def test_worldvpn_servers_html
    body = <<~HTML
      <span>theme version 7.3.0.1 is not a server</span>
      <table>
        <tr>
          <td>Germany S1</td>
          <td>116.203.253.222</td>
          <td>de1.ocservvpn.com</td>
        </tr>
        <tr>
          <td>Noise</td>
          <td>203.0.113.99</td>
          <td>example.com</td>
        </tr>
      </table>
    HTML
    assert_equal ["116.203.253.222"], P.parse("worldvpn_servers_html", body)
  end

  def test_freevpn_us_status_html
    body = <<~HTML
      <tr data-type="openvpn" data-host="ovpn-ee-1.vpnv.cc"></tr>
      <tr data-type="wireguard" data-host="wireguard-us-2.vpnv.cc"></tr>
      <tr data-type="pptp" data-host="pptp-fr-1.vpnv.cc"></tr>
      <tr data-type="ssh" data-host="ssh-us-1.vpnv.cc"></tr>
      <tr data-type="v2ray" data-host="v2ray-fr-1.vpnv.cc"></tr>
    HTML
    assert_equal ["ovpn-ee-1.vpnv.cc", "wireguard-us-2.vpnv.cc", "pptp-fr-1.vpnv.cc"],
                 P.parse("freevpn_us_status_html", body)
  end

  def test_wlvpn_server_list_xml
    body = <<~XML
      <wlvpnserverList>
        <server name="nyc-a01.wlvpn.com" ip="173.255.160.132" status="1" visible="1" />
        <server name="down.wlvpn.com" ip="203.0.113.9" status="0" visible="1" />
        <server name="hidden.wlvpn.com" ip="203.0.113.10" status="1" visible="0" />
        <server name="duplicate.wlvpn.com" ip="173.255.160.132" status="1" visible="1" />
      </wlvpnserverList>
    XML
    assert_equal ["173.255.160.132"], P.parse("wlvpn_server_list_xml", body)
  end

  def test_vpngate_csv
    body = "*vpn_servers\n#HostName,IP,...\npublic-vpn-1,219.100.37.224,score,...\n"
    assert_equal ["219.100.37.224"], P.parse("vpngate_csv", body)
  end

  def test_schema_drift_raises_parse_error
    assert_raises(P::ParseError) { P.parse("aws_json", "{}") }
    assert_raises(P::ParseError) { P.parse("mullvad_relays_json", "[]") }
    assert_raises(P::ParseError) { P.parse("aws_json", "not json") }
    assert_raises(P::ParseError) { P.parse("nope_parser", "x") }
  end

  private

  def stored_zip(entries)
    local = +"".b
    central = +"".b
    entries.each do |name, content|
      name = name.b
      content = content.b
      crc = Zlib.crc32(content)
      offset = local.bytesize
      local << ["PK\x03\x04".b, 20, 0, 0, 0, 0, crc, content.bytesize, content.bytesize,
                name.bytesize, 0].pack("a4vvvvvVVVvv")
      local << name << content
      central << ["PK\x01\x02".b, 20, 20, 0, 0, 0, 0, crc, content.bytesize, content.bytesize,
                  name.bytesize, 0, 0, 0, 0, 0, offset].pack("a4vvvvvvVVVvvvvvVV")
      central << name
    end
    eocd = ["PK\x05\x06".b, 0, 0, entries.length, entries.length, central.bytesize,
            local.bytesize, 0].pack("a4vvvvVVv")
    local << central << eocd
  end
end

class CidrUtilsTest < Minitest::Test
  def test_ranges_by_family_merges_and_splits
    out = OpenASN::CidrUtils.ranges_by_family(["1.0.0.0/25", "1.0.0.128/25", "junk", "2001:db8::/64"])
    assert_equal [[IPAddr.new("1.0.0.0").to_i, IPAddr.new("1.0.0.255").to_i]], out[:ipv4]
    assert_equal 1, out[:ipv6].length
  end
end

class TierBExecutorTest < Minitest::Test
  APPLE = "https://mask-api.icloud.com/egress-ip-ranges.csv"

  def setup
    super
    FixtureData.install_canonical(@test_data_dir)
    # Only apple enabled: the executor must not touch other sources.
    configure do |c|
      c.tier_b = { apple_relay: true, tor: false, clouds: false,
                   vpn_providers: false, zscaler: false, nazgul_mixed: false }
    end
  end

  def execute(force: true)
    http = OpenASN::HttpClient.new(user_agent: OpenASN.configuration.user_agent,
                                   logger: OpenASN.configuration.logger)
    OpenASN::TierB.new(OpenASN.configuration, http).execute(force: force)
  end

  def test_fetches_parses_aggregates_and_classification_uses_it
    stub_request(:get, APPLE).to_return(status: 200, body: "1.0.30.0/25,US,,\n1.0.30.128/25,US,,\n")

    assert execute
    # merged into ONE range and live for classification:
    r = OpenASN.lookup("1.0.30.10")
    assert_equal :relay, r.verdict
    assert_equal "iCloud Private Relay", r.provider

    status = OpenASN.dataset_info[:tier_b_status][:apple_private_relay]
    assert_equal 1, status[:records][:ipv4]
    assert_nil status[:last_error]
  end

  def test_http_failure_keeps_stale_data_and_records_error
    stub_request(:get, APPLE).to_return(status: 200, body: "1.0.30.0/24,US,,\n")
    assert execute
    assert_equal :relay, OpenASN.lookup("1.0.30.10").verdict

    stub_request(:get, APPLE).to_return(status: 500)
    refute execute # nothing changed…
    OpenASN.reset!
    configure do |c|
      c.data_dir = @test_data_dir
      c.tier_b = { apple_relay: true, tor: false, clouds: false,
                   vpn_providers: false, zscaler: false, nazgul_mixed: false }
    end
    # …and yesterday's overlay still classifies (keep-stale):
    assert_equal :relay, OpenASN.lookup("1.0.30.10").verdict
    store = OpenASN::OverlayStore.new(@test_data_dir)
    assert_match(/HTTP 500/, store.source_state("apple_private_relay")["last_error"])
  end

  def test_empty_parse_is_treated_as_upstream_breakage
    stub_request(:get, APPLE).to_return(status: 200, body: "1.0.30.0/24,US,,\n")
    assert execute
    stub_request(:get, APPLE).to_return(status: 200, body: "\n\n")
    refute execute
    store = OpenASN::OverlayStore.new(@test_data_dir)
    assert_match(/0 ranges/, store.source_state("apple_private_relay")["last_error"])
    # stale data still live:
    assert_equal :relay, OpenASN.lookup("1.0.30.10").verdict
  end

  def test_cadence_prevents_refetching_fresh_sources
    stub = stub_request(:get, APPLE).to_return(status: 200, body: "1.0.30.0/24,US,,\n")
    assert execute(force: true)
    refute execute(force: false) # fresh (24h cadence) → skipped
    assert_requested(stub, times: 1)
  end

  def test_not_modified_is_clean_keep_current_not_failure
    File.write(File.join(@test_data_dir, "fetch-manifest.json"), JSON.generate({
      schema_version: 1,
      sources: [{ id: "apple_private_relay", url: APPLE,
                  parser: "csv_cidr_first_column", maps_to: "relay",
                  provider: "iCloud Private Relay", cadence_hours: 0 }]
    }))
    stub_request(:get, APPLE).to_return(status: 200, body: "1.0.30.0/24,US,,\n",
                                        headers: { "ETag" => '"apple-1"' })
    assert execute(force: false)

    stub_request(:get, APPLE)
      .with(headers: { "If-None-Match" => '"apple-1"' })
      .to_return(status: 304)
    refute execute(force: false)

    state = OpenASN::OverlayStore.new(@test_data_dir).source_state("apple_private_relay")
    assert_nil state["last_error"]
    assert_equal :relay, OpenASN.lookup("1.0.30.10").verdict
  end

  def test_unknown_parser_is_skipped_gracefully
    File.write(File.join(@test_data_dir, "fetch-manifest.json"), JSON.generate({
      schema_version: 1,
      sources: [{ id: "apple_private_relay", url: APPLE,
                  parser: "quantum_parser_from_the_future", maps_to: "relay" }]
    }))
    refute execute # no crash, no fetch
  end

  def test_azure_page_resolver
    configure do |c|
      c.tier_b = { apple_relay: false, tor: false, clouds: true,
                   vpn_providers: false, zscaler: false, nazgul_mixed: false }
    end
    File.write(File.join(@test_data_dir, "fetch-manifest.json"), JSON.generate({
      schema_version: 1,
      sources: [{ id: "azure", resolver: "azure_download_page",
                  page_url: "https://www.microsoft.com/en-us/download/details.aspx?id=56519",
                  parser: "azure_servicetags_json", maps_to: "hosting", provider: "azure",
                  cadence_hours: 168 }]
    }))
    stub_request(:get, "https://www.microsoft.com/en-us/download/details.aspx?id=56519")
      .to_return(status: 200, body: '<a href="https://download.microsoft.com/download/7/1/d/ServiceTags_Public_20260629.json">x</a>')
    stub_request(:get, "https://download.microsoft.com/download/7/1/d/ServiceTags_Public_20260629.json")
      .to_return(status: 200, body: JSON.generate({ values: [{ properties: { addressPrefixes: ["13.64.0.0/16"] } }] }))

    assert execute
    assert_equal :hosting, OpenASN.lookup("13.64.10.10").verdict
    assert_equal "azure", OpenASN.lookup("13.64.10.10").provider
  end

  def test_post_form_sources
    configure do |c|
      c.tier_b = { apple_relay: true, tor: false, clouds: false,
                   vpn_providers: false, zscaler: false, nazgul_mixed: false }
    end
    File.write(File.join(@test_data_dir, "fetch-manifest.json"), JSON.generate({
      schema_version: 1,
      sources: [{ id: "apple_private_relay", url: APPLE, method: "POST",
                  form: { action: "vpn_servers", protocol: "udp" },
                  parser: "plain_cidr_per_line", maps_to: "relay",
                  provider: "Post Relay", cadence_hours: 0 }]
    }))
    stub_request(:post, APPLE)
      .with(body: "action=vpn_servers&protocol=udp")
      .to_return(status: 200, body: "1.0.30.0/24\n")

    assert execute
    assert_equal "Post Relay", OpenASN.lookup("1.0.30.10").provider
  end

  def test_resolves_manifest_hostnames_when_explicitly_enabled
    old_resolver = OpenASN::TierB.dns_resolver
    OpenASN::TierB.dns_resolver = ->(host) { host == "relay.example.test" ? ["1.0.30.10"] : [] }
    File.write(File.join(@test_data_dir, "fetch-manifest.json"), JSON.generate({
      schema_version: 1,
      sources: [{ id: "apple_private_relay", url: APPLE,
                  parser: "plain_cidr_per_line", maps_to: "relay",
                  provider: "Test Relay", cadence_hours: 0,
                  resolve_hostnames: true }]
    }))
    stub_request(:get, APPLE).to_return(status: 200, body: "relay.example.test\n")

    assert execute
    r = OpenASN.lookup("1.0.30.10")
    assert_equal :relay, r.verdict
    assert_equal "Test Relay", r.provider
  ensure
    OpenASN::TierB.dns_resolver = old_resolver
  end
end
