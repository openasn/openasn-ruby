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

  def test_schema_drift_raises_parse_error
    assert_raises(P::ParseError) { P.parse("aws_json", "{}") }
    assert_raises(P::ParseError) { P.parse("aws_json", "not json") }
    assert_raises(P::ParseError) { P.parse("nope_parser", "x") }
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
end
