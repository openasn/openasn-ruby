# frozen_string_literal: true

require "test_helper"

class IPTest < Minitest::Test
  def test_fast_v4_path_agrees_with_ipaddr
    %w[0.0.0.0 255.255.255.255 8.8.8.8 100.64.0.1 1.2.3.4 192.168.1.254].each do |ip|
      assert_equal [:ipv4, IPAddr.new(ip).to_i], OpenASN::IP.parse(ip), ip
    end
  end

  def test_v6
    assert_equal [:ipv6, IPAddr.new("2001:db8::1").to_i], OpenASN::IP.parse("2001:db8::1")
  end

  def test_v4_mapped_v6_classifies_as_the_embedded_v4
    assert_equal [:ipv4, IPAddr.new("1.2.3.4").to_i], OpenASN::IP.parse("::ffff:1.2.3.4")
    assert_equal [:ipv4, IPAddr.new("1.2.3.4").to_i], OpenASN::IP.parse(IPAddr.new("::ffff:1.2.3.4"))
  end

  def test_ipaddr_instances_accepted
    assert_equal [:ipv4, IPAddr.new("9.9.9.9").to_i], OpenASN::IP.parse(IPAddr.new("9.9.9.9"))
  end

  def test_rejects_garbage
    ["", "banana", "1.2.3", "1.2.3.4.5", "999.1.1.1", "1.2.3.256", "1..2.3", nil, 42, :ip].each do |bad|
      assert_raises(OpenASN::InvalidIPError, bad.inspect) { OpenASN::IP.parse(bad) }
    end
  end

  def test_leading_zero_octets_rejected_not_misparsed
    # "010" is octal in some stacks and decimal in others — refusing beats
    # silently classifying the wrong address.
    assert_raises(OpenASN::InvalidIPError) { OpenASN::IP.parse("010.1.2.3") }
  end

  def test_invalid_ip_error_is_an_argument_error
    assert_operator OpenASN::InvalidIPError, :<, ArgumentError
  end
end

class BinaryFormatTest < Minitest::Test
  def test_golden_header_bytes
    # Byte-exact FORMAT.md conformance: one IPv4 record, known values.
    path = File.join(@test_data_dir, "golden.bin")
    FixtureData.write_artifact(path, family: :ipv4,
                                     base: [[0x01020304, 0x010203FF, 65_001, 0x0201]])
    bytes = File.binread(path)
    assert_equal "4f41534e", bytes[0, 4].unpack1("H*")             # "OASN"
    assert_equal "0104", bytes[4, 2].unpack1("H*")                 # v1, ipv4
    assert_equal "0000", bytes[6, 2].unpack1("H*")                 # reserved
    assert_equal FixtureData::BUILD_TS, bytes[8, 8].unpack1("Q>")
    assert_equal [1, 0, 0, 0], bytes[16, 16].unpack("NNNN")
    assert_equal "01020304" "010203ff" "0000fde9" "0201", bytes[32, 14].unpack1("H*")

    parsed = OpenASN::BinaryFormat.parse_artifact(bytes)
    assert_equal [65_001, 0x0201], parsed[:base].find(0x01020310)
  end

  def test_rejects_bad_magic_and_versions_and_truncation
    path = File.join(@test_data_dir, "x.bin")
    FixtureData.write_artifact(path, family: :ipv4, base: [[1, 2, 3, 0]])
    good = File.binread(path)

    assert_raises(OpenASN::FormatError) { OpenASN::BinaryFormat.parse_artifact("JUNK#{good[4..]}") }

    v2 = good.dup
    v2.setbyte(4, 0x02)
    assert_raises(OpenASN::FormatError) { OpenASN::BinaryFormat.parse_artifact(v2) }

    assert_raises(OpenASN::FormatError) { OpenASN::BinaryFormat.parse_artifact(good[0..-2]) }
    assert_raises(OpenASN::FormatError) { OpenASN::BinaryFormat.parse_artifact(good + "\x00") }
  end

  def test_org_index
    path = File.join(@test_data_dir, "orgs.bin")
    FixtureData.write_orgs(path, { 1 => "One", 300 => "Tres — ñ", 65_000 => "Last" })
    idx = OpenASN::BinaryFormat::OrgIndex.load(path)
    assert_equal "One", idx.name(1)
    assert_equal "Tres — ñ", idx.name(300)
    assert_equal "Last", idx.name(65_000)
    assert_nil idx.name(2)
    assert_equal Encoding::UTF_8, idx.name(300).encoding
  end

  def test_flag_names
    f = OpenASN::BinaryFormat::FLAG_BAD_ASN | OpenASN::BinaryFormat::FLAG_CDN
    assert_equal %i[bad_asn cdn], OpenASN::BinaryFormat.flag_names(f)
  end
end

class ArraysModeTest < Minitest::Test
  # :packed and :arrays must be indistinguishable except for speed/memory.
  def test_modes_agree_on_every_fixture_ip
    FixtureData.install_all(@test_data_dir)

    results = {}
    %i[packed arrays].each do |mode|
      OpenASN.reset!
      OpenASN.configure do |c|
        c.data_dir = @test_data_dir
        c.memory_mode = mode
        c.tier_b = { apple_relay: true, tor: true, clouds: true,
                     vpn_providers: true, zscaler: true, nazgul_mixed: true }
      end
      probes = (0..40).flat_map { |i| ["1.0.#{i}.1", "1.0.#{i}.130", "1.0.#{i}.255"] }
      probes += %w[2001:db8:1::1 2001:db8:3::9 2001:db8:4::5 2001:db8:9::1 8.8.8.8]
      results[mode] = probes.map { |ip| OpenASN.lookup(ip).to_h }
    end

    assert_equal results[:packed], results[:arrays]
  end
end
