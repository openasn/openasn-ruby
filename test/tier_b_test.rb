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
    body = <<~HTML
      <tr><td>Australia</td><td>Sydney</td><td>AU-STREAM.JUMPTOSERVER.COM</td></tr>
      <tr><td>Canada</td><td>ca1.<span>vpn.giganews.com</span></td></tr>
    HTML
    assert_equal ["au-stream.jumptoserver.com", "ca1.vpn.giganews.com"],
                 P.parse("html_table_hostnames", body.b)
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

  def test_ovpn_status_servers_json
    body = JSON.generate({
      data: [
        { name: "VPN26", ip: "217.138.204.35", online: true },
        { name: "VPN27", ip: "192.0.2.10", online: false }
      ]
    })
    assert_equal ["217.138.204.35"], P.parse("ovpn_status_servers_json", body)
  end

  def test_anonine_status_json
    body = JSON.generate([
      {
        primary_ip: "198.57.26.18",
        alias: "ca-tr.anonine.net",
        servers: [{ host: "ca-tr.anonine.net", ips: ["198.57.26.18", "198.57.26.19"] }]
      },
      {
        primary_ip: "80.90.55.57",
        servers: [{ host: "lu.anonine.net", ips: ["80.90.55.168"] }]
      }
    ])
    assert_equal ["198.57.26.18", "198.57.26.19", "80.90.55.57", "80.90.55.168"],
                 P.parse("anonine_status_json", body)
  end

  def test_azirevpn_locations_json
    body = JSON.generate({ locations: [{ name: "se-sto", pool: "se-sto.azirevpn.net" },
                                       { name: "nl-ams", pool: "nl-ams.azirevpn.net" }] })
    assert_equal ["se-sto.azirevpn.net", "nl-ams.azirevpn.net"], P.parse("azirevpn_locations_json", body)
  end

  def test_vpnac_status_html
    body = <<~HTML
      <table>
        <tr><td>Australia</td><td>au1.vpn.ac</td><td>1%</td></tr>
        <tr><td>Not a cell hostname: ignored.vpn.ac</td></tr>
        <a href="https://blog.vpn.ac">blog.vpn.ac</a>
      </table>
    HTML
    assert_equal ["au1.vpn.ac"], P.parse("vpnac_status_html", body)
  end

  def test_trustzone_servers_html
    body = <<~HTML
      <a href="/setup/ios/ovpn/us-wa">United States-Washington us-wa.trust.zone</a>
      <a href="/">www.trust.zone</a>
      <span>Japan-Netflix jp-nfx.trust.zone VIP</span>
    HTML
    assert_equal ["us-wa.trust.zone", "jp-nfx.trust.zone"], P.parse("trustzone_servers_html", body)
  end

  # Shape verified live 2026-09-05 after SlickVPN's site redesign: each
  # location card exposes the connect address in a copy button's data-host.
  def test_slickvpn_locations_html
    body = <<~HTML
      <div class="card"><span>Active</span>
        <button data-host="gw2.ams3.slickvpn.com" title="Copy server address">Copy</button></div>
      <div class="card"><span>Active</span>
        <button data-host="gw1.bos1.slickvpn.com" title="Copy server address">Copy</button></div>
      <a href="https://members.newsdemon.com/vpn/2025/SV-2025-Amsterdam.ovpn">config</a>
      <button data-host="tracker.example.com">not a slickvpn host</button>
    HTML
    assert_equal ["gw2.ams3.slickvpn.com", "gw1.bos1.slickvpn.com"],
                 P.parse("slickvpn_locations_html", body)
    assert_raises(P::ParseError) { P.parse("slickvpn_locations_html", "<div>no servers</div>") }
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
        <server visible='1' status='1' ip='173.255.160.133' name='nyc-a02.wlvpn.com' />
        <server name="down.wlvpn.com" ip="203.0.113.9" status="0" visible="1" />
        <server name="hidden.wlvpn.com" ip="203.0.113.10" status="1" visible="0" />
        <server name="duplicate.wlvpn.com" ip="173.255.160.132" status="1" visible="1" />
      </wlvpnserverList>
    XML
    assert_equal ["173.255.160.132", "173.255.160.133"], P.parse("wlvpn_server_list_xml", body)
  end

  def test_vpngate_csv
    body = "*vpn_servers\n#HostName,IP,...\npublic-vpn-1,219.100.37.224,score,...\n"
    assert_equal ["219.100.37.224"], P.parse("vpngate_csv", body)
  end

  # --- verified crawler / agent recognition lists ---------------------------

  def test_crawler_ipranges_json_google_shape
    body = JSON.generate({ creationTime: "2026-09-04T14:46:55.000000",
                           prefixes: [{ ipv6Prefix: "2001:4860:4801:10::/64" },
                                      { ipv4Prefix: "66.249.64.0/27" }] })
    assert_equal ["2001:4860:4801:10::/64", "66.249.64.0/27"], P.parse("crawler_ipranges_json", body)
  end

  # Bing, OpenAI, Perplexity and Common Crawl all copied Google's shape
  # verbatim — one parser, no gem release per new crawler feed.
  def test_crawler_ipranges_json_covers_every_publisher_of_that_shape
    bing = JSON.generate({ creationTime: "2024-01-03T10:00:00.121331",
                           prefixes: [{ ipv4Prefix: "157.55.39.0/24" }] })
    ccbot = JSON.generate({ synctoken: "20260811134000", notes: "IP ranges used by CCBot.",
                            prefixes: [{ ipv6Prefix: "2600:1f28:365:8000::/56" }] })
    assert_equal ["157.55.39.0/24"], P.parse("crawler_ipranges_json", bing)
    assert_equal ["2600:1f28:365:8000::/56"], P.parse("crawler_ipranges_json", ccbot)
  end

  def test_crawler_ipranges_json_rejects_drift
    assert_raises(P::ParseError) { P.parse("crawler_ipranges_json", JSON.generate({ prefixes: [] })) }
    assert_raises(P::ParseError) { P.parse("crawler_ipranges_json", "[]") }
    # An HTML error page served at a .json URL must not parse as "no data".
    assert_raises(P::ParseError) { P.parse("crawler_ipranges_json", "<!DOCTYPE html><html>") }
  end

  # --- additional cloud / platform publications ------------------------------

  def test_fastly_public_ip_list_json
    body = JSON.generate({ addresses: ["23.235.32.0/20"], ipv6_addresses: ["2a04:4e40::/32"] })
    assert_equal ["23.235.32.0/20", "2a04:4e40::/32"], P.parse("fastly_public_ip_list_json", body)
  end

  # GitHub mixes CIDR arrays with ssh keys, booleans and objects, and adds
  # service groups regularly — take every CIDR, ignore everything else.
  def test_github_meta_json_takes_every_cidr_group_and_ignores_the_rest
    body = JSON.generate({ verifiable_password_authentication: true,
                           ssh_key_fingerprints: { SHA256_RSA: "uNiVztksC..." },
                           ssh_keys: ["ssh-ed25519 AAAAC3Nz"],
                           hooks: ["192.30.252.0/22", "2a0a:a440::/29"],
                           actions: ["4.148.0.0/16"],
                           domains: { website: ["*.github.com"] } })
    assert_equal ["192.30.252.0/22", "2a0a:a440::/29", "4.148.0.0/16"],
                 P.parse("github_meta_json", body)
  end

  def test_atlassian_ipranges_json
    body = JSON.generate({ creationDate: "2026-09-01", syncToken: 1,
                           items: [{ network: "13.52.5.0", mask_len: 24, cidr: "13.52.5.0/24",
                                     product: ["jira"], direction: ["egress"] }] })
    assert_equal ["13.52.5.0/24"], P.parse("atlassian_ipranges_json", body)
  end

  # Cisco's SSE geofeed publishes 142 single egress addresses with a bogus
  # /32 mask. Widening one of those claims 2^96 addresses on the evidence of
  # a pinhole, so a row with host bits set becomes a host route.
  def test_geofeed_csv_no_widen_host_routes_instead_of_widening
    body = <<~CSV
      46.255.40.0/24,US,US-TX,Dallas,
      2a04:e4c0:aa::/48,AE,,Dubai,
      2603:5004:e0:107::135b/32,DE,DE-HE,FRANKFURT,
      151.186.172.35/32,,
      198.51.100.7/24,US,,,
    CSV
    tokens = P.parse("geofeed_csv_no_widen", body)
    assert_equal ["46.255.40.0/24", "2a04:e4c0:aa::/48", "2603:5004:e0:107::135b/128",
                  "151.186.172.35/32", "198.51.100.7/32"], tokens
  end

  def test_geofeed_csv_no_widen_refuses_an_empty_feed
    assert_raises(P::ParseError) { P.parse("geofeed_csv_no_widen", "\n# nothing here\n") }
  end

  # Cato's page concatenates dash-delimited ranges inside single table cells
  # ("140.82.194.1 - 140.82.194.254113.30.130.1 - …"), which is how you get
  # corrupt octets out of it. Requiring a prefix length is what keeps them out.
  def test_cato_pop_html_takes_cidrs_and_ignores_the_dash_range_tables
    body = +"<html><body><td>140.82.194.1 - 140.82.194.254113.30.130.1 - 113.30.130.254</td>"
    body << "<td>version 1.2.3/4</td>"
    35.times { |i| body << "<p>45.#{62 + i}.176.0/20</p>" }
    body << "<p>216.205.112.0/20</p><p>216.205.112.0/20</p></body></html>"
    tokens = P.parse("cato_pop_html", body)
    assert_equal 36, tokens.length          # 35 unique + one duplicate collapsed
    assert_includes tokens, "45.62.176.0/20"
    refute_includes tokens, "1.2.3/4"       # prefix length 4 is outside 19..32
    refute(tokens.any? { |t| t.start_with?("06.") || t.start_with?("14.94") })
  end

  def test_cato_pop_html_refuses_a_page_that_lost_its_list
    assert_raises(P::ParseError) { P.parse("cato_pop_html", "<html><p>45.62.176.0/20</p></html>") }
  end

  # OVPN's client bootstrap API: whole fleet in one request. An offline
  # server is still OVPN egress, so `online` must NOT be a filter — and
  # nothing outside `datacenters` is read, because `shadowsocks` holds a
  # shared credential.
  def test_ovpn_client_entry_json
    body = JSON.generate({ success: true,
                           datacenters: [{ slug: "vienna", city: "Vienna",
                                           ping_address: "37.120.212.227",
                                           pools: ["pool-1.prd.at.vienna.ovpn.com"],
                                           servers: [{ ip: "37.120.212.227", ptr: "vpn44.prd.vienna.ovpn.com",
                                                       online: true },
                                                     { ip: "37.120.212.228", online: false }] }],
                           shadowsocks: { password: "must-not-leak" } })
    assert_equal ["37.120.212.227", "37.120.212.228"], P.parse("ovpn_client_entry_json", body)
  end

  def test_ovpn_client_entry_json_rejects_drift
    assert_raises(P::ParseError) { P.parse("ovpn_client_entry_json", JSON.generate({ datacenters: [] })) }
    assert_raises(P::ParseError) { P.parse("ovpn_client_entry_json", JSON.generate({ success: true })) }
    assert_raises(P::ParseError) do
      P.parse("ovpn_client_entry_json", JSON.generate({ success: true, datacenters: [{ slug: "x" }] }))
    end
  end

  # --- documentation-as-data clouds ------------------------------------------

  # Scaleway's page has TWO bullet lists of addresses. Only the first is
  # prefix data; the second is DNS/NTP resolver hosts. Getting the section
  # boundary wrong is the whole risk, so the fixture reproduces it.
  def test_scaleway_network_mdx_reads_only_the_ip_ranges_section
    body = <<~MDX
      ---
      title: Scaleway network information
      dates:
        validation: 2025-06-27
      ---

      ## IP ranges used by Scaleway

      Currently, we use the following IP ranges:

      ### IPv4
      * `62.210.0.0/16`
      * `195.154.0.0/16`
      * `212.129.0.0/18`
      * `62.4.0.0/19`
      * `212.83.128.0/19`
      * `212.83.160.0/19`
      * `212.47.224.0/19`
      * `163.172.0.0/16`
      * `51.15.0.0/16`
      * `151.115.0.0/16`
      * `51.158.0.0/15`
      * `78.232.0.0/16`

      ### IPv6
      * `2001:bc8::/32`

      ## DNS cache servers and NTP servers

      #### fr-par-1

      - `51.159.69.162`
      - `2001:bc8:408:1::12`

      ## Additional Dedibox services

      Our monitoring servers are located in the IP subnet `62.210.16.0/24`.
    MDX
    tokens = P.parse("scaleway_network_mdx", body)
    assert_equal 13, tokens.length
    assert_includes tokens, "62.210.0.0/16"
    assert_includes tokens, "2001:bc8::/32"
    refute_includes tokens, "51.159.69.162"
    refute_includes tokens, "62.210.16.0/24"
  end

  def test_scaleway_network_mdx_refuses_a_truncated_page
    assert_raises(P::ParseError) do
      P.parse("scaleway_network_mdx", "## IP ranges used by Scaleway\n\n### IPv4\n* `62.210.0.0/16`\n")
    end
  end

  # The single most dangerous document in the manifest: 509 of IBM's 759
  # CIDRs are RFC1918. Two independent guards must both hold.
  def test_ibm_cloud_ip_ranges_markdown_keeps_public_sections_only
    body = <<~MD
      ---
      last-updated: 2026-06-09
      ---

      ## Front-end (public) network
      {: #front-end-network}

      |Data center|City|IP range|
      |---|---|---|
      |ams03|Amsterdam |159.8.198.0/23|
      |dal05|Dallas |50.23.203.0/24  \\n 108.168.157.0/24  \\n 173.192.117.0/24|
      FRONT_END_FILLER

      ## Load balancer IPs
      {: #load-balancer-ips}

      |Data center|City|IP range|
      |---|---|---|
      |ams03|Amsterdam|159.8.197.0/24|

      ## Back-end (private) network
      {: #back-end-network}

      |Data center|City|IP range|
      |---|---|---|
      |ams03|Amsterdam|10.2.64.0/19|

      ### Customer private network space

      |IP range|
      |---|
      |172.16.0.0/12|

      ## Legacy networks
      {: #legacy-networks}

      |IP range|
      |---|
      |12.96.160.0/24|
      |216.12.193.9|

      ## Red Hat Enterprise Linux server requirements

      | Server location | Permitted data centers | IP ranges |
      |---|---|---|
      | Amsterdam (ams03) | fra02 | 161.26.36.0/22 |

      ## Windows virtual server instance requirements

      |Data Center|City|BCR IP Range|
      |---|---|---|
      |tok04|Tokyo|10.3.17.0/24 \\n 10.192.0.0/16|
    MD
    # enough real rows to clear the >= 50 sanity floor the parser enforces
    filler = (1..60).map { |i| "|dc#{i}|City |169.4#{i / 10}.#{i}.0/24|" }.join("\n")
    tokens = P.parse("ibm_cloud_ip_ranges_markdown", body.sub("FRONT_END_FILLER", filler))
    # multi-CIDR cells split on the LITERAL backslash-n
    assert_includes tokens, "108.168.157.0/24"
    assert_includes tokens, "173.192.117.0/24"
    assert_includes tokens, "159.8.197.0/24"
    # bare legacy address becomes a host route
    assert_includes tokens, "216.12.193.9/32"
    # private space never survives, by section AND by RFC1918 guard
    refute_includes tokens, "10.2.64.0/19"
    refute_includes tokens, "172.16.0.0/12"
    refute_includes tokens, "10.192.0.0/16"
    # third-party endpoints a customer must reach are not IBM space
    refute_includes tokens, "161.26.36.0/22"
  end

  def test_ibm_cloud_ip_ranges_markdown_refuses_a_page_that_lost_its_public_tables
    body = "## Back-end (private) network\n\n|dc|city|range|\n|---|---|---|\n|ams03|Amsterdam|10.2.64.0/19|\n"
    assert_raises(P::ParseError) { P.parse("ibm_cloud_ip_ranges_markdown", body) }
  end

  # OVH's 24 cluster gateways are the point of the recipe; the country VIP
  # tables come along because they are equally OVH datacenter space.
  def test_ovh_web_hosting_cluster_md_takes_vips_and_the_outgoing_gateway
    cluster = lambda do |n, v4, v6, cdn, gw|
      <<~MD
        #### Cluster #{n}

        Below are the **cluster** IP addresses for each country (for geolocation):
        | Country        | Country Code | IPv4           | IPv6                 |
        | -------------- | ------------ | -------------- | -------------------- |
        | France         | FR           | #{v4}  | #{v6}    |
        If you have activated the **Shared CDN** option on your Web Hosting, use this IP address:
        ```bash
        #{cdn}
        ```
        If you need the **outgoing IP address** of the Web Hosting cluster (gateway), use this IP address:
        ```bash
        #{gw}
        ```
      MD
    end
    body = +"---\nlastUpdated: 2026-07-21\n---\n\n# Web Hosting - List of IP addresses by cluster\n\n"
    # 60 synthetic clusters clear the >= 100 sanity floor the parser enforces
    60.times { |i| body << cluster.call(i, "188.165.61.#{i}", "2001:41d0:301::#{i}", "46.105.204.#{i}", "91.134.248.#{i}") }
    tokens = P.parse("ovh_web_hosting_cluster_md", body)
    assert_includes tokens, "188.165.61.7/32"
    assert_includes tokens, "2001:41d0:301::7/128"
    assert_includes tokens, "46.105.204.7/32"
    assert_includes tokens, "91.134.248.7/32"
    assert_equal 240, tokens.length
  end

  def test_ovh_web_hosting_cluster_md_refuses_a_page_that_lost_its_tables
    assert_raises(P::ParseError) do
      P.parse("ovh_web_hosting_cluster_md", "# Web Hosting\n\nNo addresses here any more.\n")
    end
  end

  def test_json_string_array
    assert_equal ["1.2.3.0/24", "2001:db8::/32"],
                 P.parse("json_string_array", JSON.generate(["1.2.3.0/24", "2001:db8::/32"]))
    assert_raises(P::ParseError) { P.parse("json_string_array", JSON.generate({})) }
    assert_raises(P::ParseError) { P.parse("json_string_array", "[]") }
  end

  def test_schema_drift_raises_parse_error
    assert_raises(P::ParseError) { P.parse("aws_json", "{}") }
    assert_raises(P::ParseError) { P.parse("mullvad_relays_json", "[]") }
    assert_raises(P::ParseError) { P.parse("aws_json", "not json") }
    assert_raises(P::ParseError) { P.parse("nope_parser", "x") }
    assert_raises(P::ParseError) { P.parse("fastly_public_ip_list_json", "{}") }
    assert_raises(P::ParseError) { P.parse("github_meta_json", JSON.generate({ ssh_keys: ["x"] })) }
    assert_raises(P::ParseError) { P.parse("atlassian_ipranges_json", "{}") }
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

  # The headline end-to-end guarantee of the 2026-09 crawler work. Measured
  # on the real feeds: 27 of 28 Bingbot prefixes and 100% of OpenAI's sit
  # inside Azure's published ranges, and 23 of 317 Googlebot prefixes sit
  # inside GCP's. So the cloud overlay legitimately WINS the verdict and the
  # provider slot — and the crawler identity must survive that anyway. This
  # test builds exactly that collision: one IP claimed by both a cloud
  # source and a crawler source.
  def test_crawler_attribution_survives_a_cloud_overlay_claiming_the_same_ip
    cloud = "https://cloud.example/ranges.json"
    bot = "https://operator.example/gptbot.json"
    File.write(File.join(@test_data_dir, "fetch-manifest.json"), JSON.generate({
      schema_version: 1,
      sources: [
        { id: "aws", url: cloud, parser: "json_string_array", maps_to: "hosting",
          provider: "cloudco", cadence_hours: 24 },
        { id: "openai_gptbot", url: bot, parser: "crawler_ipranges_json", maps_to: "hosting",
          provider: "gptbot", role: "verified_crawler", cadence_hours: 24 }
      ]
    }))
    # The crawler /28 sits INSIDE the cloud /16.
    stub_request(:get, cloud).to_return(status: 200, body: JSON.generate(["23.102.0.0/16"]))
    stub_request(:get, bot).to_return(status: 200, body: JSON.generate(
      { creationTime: "2026-09-04T18:03:29.248484", prefixes: [{ ipv4Prefix: "23.102.140.112/28" }] }
    ))
    configure { |c| c.tier_b = { clouds: true, verified_crawlers: true } }
    assert execute

    inside = OpenASN.lookup("23.102.140.115")
    assert_equal :hosting, inside.verdict          # the network really is a datacenter
    assert_equal "cloudco", inside.provider        # the cloud overlay legitimately wins
    assert_equal "gptbot", inside.crawler          # …and the identity still surfaces
    assert_predicate inside, :verified_crawler?
    assert_includes inside.context_flags, :verified_crawler

    # An address in the cloud range but outside the crawler /28 gets the same
    # verdict and NO attribution — the whole point of per-prefix lists.
    outside = OpenASN.lookup("23.102.9.9")
    assert_equal :hosting, outside.verdict
    assert_equal "cloudco", outside.provider
    assert_nil outside.crawler
    refute_predicate outside, :verified_crawler?
  end

  # A user-triggered fetcher is a human waiting on a page, so it must never
  # be reported as autonomous crawler traffic (see Classifier::CRAWLER_ROLES).
  def test_verified_fetcher_role_round_trips_through_the_store
    url = "https://operator.example/chatgpt-user.json"
    File.write(File.join(@test_data_dir, "fetch-manifest.json"), JSON.generate({
      schema_version: 1,
      sources: [{ id: "openai_chatgpt_user", url: url, parser: "crawler_ipranges_json",
                  maps_to: "hosting", provider: "chatgpt-user", role: "verified_fetcher",
                  cadence_hours: 6 }]
    }))
    stub_request(:get, url).to_return(status: 200, body: JSON.generate(
      { creationTime: "2026-09-04T18:03:29.248484", prefixes: [{ ipv4Prefix: "1.0.30.0/24" }] }
    ))
    configure { |c| c.tier_b = { verified_crawlers: true } }
    assert execute

    assert_equal "verified_fetcher", OpenASN::OverlayStore.new(@test_data_dir)
                                                          .source_state("openai_chatgpt_user")["role"]
    r = OpenASN.lookup("1.0.30.10")
    assert_equal "chatgpt-user", r.crawler
    assert_predicate r, :verified_fetcher?
    refute_predicate r, :verified_crawler?
    assert_includes r.context_flags, :verified_fetcher
  end

  # A source with no role must behave exactly as it did before roles existed.
  def test_a_source_without_a_role_produces_no_attribution
    url = "https://cloud.example/ranges.json"
    File.write(File.join(@test_data_dir, "fetch-manifest.json"), JSON.generate({
      schema_version: 1,
      sources: [{ id: "aws", url: url, parser: "json_string_array", maps_to: "hosting",
                  provider: "cloudco", cadence_hours: 24 }]
    }))
    stub_request(:get, url).to_return(status: 200, body: JSON.generate(["1.0.30.0/24"]))
    configure { |c| c.tier_b = { clouds: true } }
    assert execute

    r = OpenASN.lookup("1.0.30.10")
    assert_equal "cloudco", r.provider
    assert_nil r.crawler
    assert_nil r.crawler_role
    assert_empty r.context_flags
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

# The bundled seed's fetch-manifest and the gem's own feature map are two
# halves of one contract, and nothing linked them before: a source could be
# added to fetch-manifest.json, ship, and be silently NEVER FETCHED because
# no feature switch listed its id (or reference a parser this gem does not
# have). Both mistakes are invisible at runtime — the executor just skips.
class BundledManifestConsistencyTest < Minitest::Test
  MANIFEST = JSON.parse(File.read(File.join(OpenASN::Snapshot::SEED_DIR, "fetch-manifest.json"))).freeze

  def manifest_ids = MANIFEST["sources"].map { |s| s["id"] }

  def mapped_ids = OpenASN::Configuration::TIER_B_SOURCE_MAP.values.flatten

  def test_every_manifest_source_is_reachable_from_some_feature_switch
    orphans = manifest_ids - mapped_ids
    assert_empty orphans, "fetch-manifest sources no feature switch can enable: #{orphans.inspect}"
  end

  def test_every_mapped_source_id_exists_in_the_manifest
    dangling = mapped_ids - manifest_ids
    assert_empty dangling, "TIER_B_SOURCE_MAP names sources the manifest does not define: #{dangling.inspect}"
  end

  def test_every_manifest_parser_is_implemented_by_this_gem
    missing = MANIFEST["sources"].map { |s| s["parser"] }.uniq.reject { |p| OpenASN::Parsers.known?(p) }
    assert_empty missing, "fetch-manifest references parsers this gem lacks: #{missing.inspect}"
  end

  def test_feature_defaults_and_source_map_cover_the_same_switches
    assert_equal OpenASN::Configuration::TIER_B_DEFAULTS.keys.sort,
                 OpenASN::Configuration::TIER_B_SOURCE_MAP.keys.sort
  end

  def test_every_source_declares_the_fields_the_executor_relies_on
    MANIFEST["sources"].each do |s|
      assert s["id"].is_a?(String), "source without an id: #{s.inspect}"
      assert s["maps_to"].is_a?(String), "#{s['id']}: missing maps_to"
      assert s["cadence_hours"].is_a?(Integer), "#{s['id']}: missing cadence_hours"
      assert s.key?("url") || s.key?("urls") || s["resolver"], "#{s['id']}: no URL or resolver"
      # `role` is optional, but when present it must be one this gem acts on,
      # otherwise the attribution silently disappears.
      if s.key?("role")
        assert_includes OpenASN::Classifier::CRAWLER_ROLES, s["role"], "#{s['id']}: unknown role"
      end
    end
  end

  # maps_to is either a verdict this gem's classifier consults or a "flag:*"
  # context flag. A typo here is a source that fetches and then does nothing.
  def test_maps_to_values_are_ones_the_classifier_acts_on
    consulted = %w[relay tor_exit vpn enterprise_gateway hosting]
    MANIFEST["sources"].each do |s|
      m = s["maps_to"]
      next if m.start_with?("flag:")

      assert_includes consulted, m, "#{s['id']}: maps_to #{m.inspect} is never consulted"
    end
  end
end
