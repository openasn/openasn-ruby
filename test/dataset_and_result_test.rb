# frozen_string_literal: true

require "test_helper"
require "digest"

class DatasetTest < Minitest::Test
  def test_falls_back_to_bundled_seed_when_data_dir_empty
    # test_data_dir is empty → the REAL bundled seed loads.
    info = OpenASN.dataset_info
    assert_equal :seed, info[:origin]
    assert_operator info[:records][:base_ipv4], :>, 100_000
  end

  def test_corrupt_data_dir_artifacts_fall_back_to_seed
    File.binwrite(File.join(@test_data_dir, "openasn-ipv4.bin"), "GARBAGE")
    File.binwrite(File.join(@test_data_dir, "openasn-ipv6.bin"), "GARBAGE")
    r = OpenASN.lookup("8.8.8.8") # must not raise
    assert_equal :hosting, r.verdict
    assert_equal :seed, OpenASN.dataset_info[:origin]
  end

  def test_manifest_checksum_mismatch_falls_back_to_seed
    FixtureData.install_canonical(@test_data_dir)
    File.write(File.join(@test_data_dir, "manifest.json"), JSON.generate({
      format_version: 1,
      edition: "core",
      build_id: Time.at(FixtureData::BUILD_TS).utc.iso8601,
      files: [
        { name: "openasn-ipv4.bin", sha256: "0" * 64 },
        { name: "openasn-ipv6.bin", sha256: Digest::SHA256.file(File.join(@test_data_dir, "openasn-ipv6.bin")).hexdigest }
      ]
    }))

    r = OpenASN.lookup("8.8.8.8")
    assert_equal :hosting, r.verdict
    assert_equal :seed, OpenASN.dataset_info[:origin]
  end

  def test_reload_under_concurrent_lookups_is_safe
    FixtureData.install_canonical(@test_data_dir)
    OpenASN.eager_load!

    # Bounded work + periodic Thread.pass: busy-spinning readers would
    # starve the reloading thread of GVL reacquisition after each file
    # read (measured: 50 reloads against 8 spinners took MINUTES) — and
    # real apps don't spin lookups back-to-back anyway. The point here is
    # correctness under interleaving, not a starvation benchmark.
    errors = Queue.new
    readers = 8.times.map do
      Thread.new do
        4_000.times do |i|
          v = OpenASN.lookup("1.0.0.42").verdict
          errors << "bad verdict #{v}" unless v == :residential_isp
          Thread.pass if (i % 200).zero?
        end
      rescue StandardError => e
        errors << "#{e.class}: #{e.message}"
      end
    end

    # Hammer swaps while readers run.
    10.times { OpenASN.dataset.reload! }
    readers.each(&:join)

    assert_empty [].tap { |a| a << errors.pop until errors.empty? }
  end

  def test_snapshot_swap_is_visible_after_reload
    FixtureData.install_canonical(@test_data_dir)
    assert_equal :data_dir, OpenASN.dataset_info[:origin]
    first_loaded_at = OpenASN.dataset_info[:loaded_at]
    OpenASN.dataset.reload!
    refute_equal first_loaded_at, OpenASN.dataset_info[:loaded_at]
  end

  def test_data_stale_on_disk_probe
    FixtureData.install_canonical(@test_data_dir) # BUILD_TS is July 2026
    refute OpenASN.data_stale_on_disk?(max_age: 100 * 365 * 86_400)
    assert OpenASN.data_stale_on_disk?(max_age: 1)
  end
end

class ResultTest < Minitest::Test
  def build(verdict) = OpenASN::Result.new(ip: "192.0.2.1", verdict: verdict)

  def test_infrastructure_and_likely_human_are_asymmetric_on_purpose
    # infrastructure: high-confidence non-eyeball
    assert build(:hosting).infrastructure?
    assert build(:vpn).infrastructure?
    assert build(:tor_exit).infrastructure?
    # likely human: includes the never-hard-block classes
    %i[residential_isp mobile relay cgnat enterprise_gateway].each do |v|
      assert build(v).likely_human?, v
      refute build(v).infrastructure?, v
    end
    # deliberately NEITHER: the app decides
    %i[business education government unknown private].each do |v|
      refute build(v).infrastructure?, v
      refute build(v).likely_human?, v
    end
  end

  def test_predicates
    assert build(:vpn).vpn?
    assert build(:hosting).hosting?
    assert build(:tor_exit).tor?
    assert build(:relay).relay?
    assert build(:mobile).mobile?
    assert build(:private).private?
    assert build(:cgnat).cgnat?
  end

  def test_no_suspicious_predicate_exists
    # `suspicious?` is a policy word — deliberately not provided (apps must
    # draw their own line). This test keeps it from sneaking in.
    refute build(:vpn).respond_to?(:suspicious?)
  end

  def test_to_h_is_stable_and_frozen_result
    r = OpenASN::Result.new(ip: "192.0.2.1", verdict: :vpn, asn: 9009, provider: "x",
                            sources: [:x4b_vpn], flags: 0x0202)
    assert r.frozen?
    h = r.to_h
    assert_equal %i[ip verdict infrastructure likely_human asn as_org category
                    network_role provider sources flags context_flags unrouted], h.keys
    assert_equal :vpn, h[:verdict]
    assert h[:infrastructure]
  end
end

class MiddlewareTest < Minitest::Test
  def app_with(env_capture)
    app = ->(env) { env_capture << env; [200, {}, ["ok"]] }
    OpenASN::Middleware.new(app)
  end

  def test_sets_result_from_remote_addr
    FixtureData.install_canonical(@test_data_dir)
    captured = []
    app_with(captured).call({ "REMOTE_ADDR" => "1.0.0.42" })
    result = captured.first["openasn.result"]
    assert_equal :residential_isp, result.verdict
  end

  def test_missing_or_invalid_ip_yields_nil_not_an_exception
    captured = []
    app_with(captured).call({})
    assert_nil captured.first["openasn.result"]

    captured = []
    app_with(captured).call({ "REMOTE_ADDR" => "banana" })
    assert_nil captured.first["openasn.result"]
  end

  def test_lookup_errors_never_break_the_request
    OpenASN.stubs(:lookup).raises(RuntimeError.new("boom"))
    captured = []
    status, = app_with(captured).call({ "REMOTE_ADDR" => "1.2.3.4" })
    assert_equal 200, status
    assert_nil captured.first["openasn.result"]
  end
end
