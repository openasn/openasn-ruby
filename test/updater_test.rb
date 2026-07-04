# frozen_string_literal: true

require "test_helper"
require "digest"

class UpdaterTest < Minitest::Test
  RELEASE = "https://github.com/openasn/openasn/releases/latest/download/"

  def setup
    super
    # Fixture "release": build artifact bytes in memory and serve via webmock.
    @v4_path = File.join(@test_data_dir, "_r_v4.bin")
    @v6_path = File.join(@test_data_dir, "_r_v6.bin")
    @orgs_path = File.join(@test_data_dir, "_r_orgs.bin")
    FixtureData.write_artifact(@v4_path, family: :ipv4, base: FixtureData.base_rows_v4,
                                         vpn: FixtureData.vpn_rows_v4, dc: FixtureData.dc_rows_v4)
    FixtureData.write_artifact(@v6_path, family: :ipv6, base: FixtureData.base_rows_v6)
    FixtureData.write_orgs(@orgs_path)
    @v4 = File.binread(@v4_path)
    @v6 = File.binread(@v6_path)
    @orgs = File.binread(@orgs_path)
    [@v4_path, @v6_path, @orgs_path].each { |p| File.delete(p) }

    @manifest = {
      format_version: 1, edition: "core", build_id: "2026-07-04T09:00:00Z",
      files: [
        { name: "openasn-ipv4.bin", sha256: Digest::SHA256.hexdigest(@v4), bytes: @v4.bytesize, records: 1 },
        { name: "openasn-ipv6.bin", sha256: Digest::SHA256.hexdigest(@v6), bytes: @v6.bytesize, records: 1 },
        { name: "openasn-orgs.bin", sha256: Digest::SHA256.hexdigest(@orgs), bytes: @orgs.bytesize, records: 3 }
      ]
    }.then { |h| JSON.generate(h) }

    # Tier B disabled for updater tests — exercised separately.
    configure { |c| c.tier_b = c.tier_b.transform_values { false } }
  end

  def stub_release!
    stub_request(:get, "#{RELEASE}manifest.json")
      .to_return(status: 200, body: @manifest, headers: { "ETag" => '"m1"' })
    stub_request(:get, "#{RELEASE}openasn-ipv4.bin").to_return(status: 200, body: @v4)
    stub_request(:get, "#{RELEASE}openasn-ipv6.bin").to_return(status: 200, body: @v6)
    stub_request(:get, "#{RELEASE}openasn-orgs.bin").to_return(status: 200, body: @orgs)
    stub_request(:get, "#{RELEASE}fetch-manifest.json")
      .to_return(status: 200, body: JSON.generate({ schema_version: 1, sources: [] }))
  end

  def test_full_update_downloads_verifies_and_swaps
    stub_release!

    assert_equal :updated, OpenASN.update!
    # Files landed atomically in data_dir:
    %w[openasn-ipv4.bin openasn-ipv6.bin openasn-orgs.bin manifest.json fetch-manifest.json].each do |f|
      assert File.exist?(File.join(@test_data_dir, f)), "missing #{f}"
    end
    # And the live dataset serves the new data, orgs included:
    r = OpenASN.lookup("1.0.0.42")
    assert_equal :residential_isp, r.verdict
    assert_equal "Fixture Residential ISP", r.as_org
    assert_equal :data_dir, OpenASN.dataset_info[:origin]
    assert_equal "2026-07-04T09:00:00Z", OpenASN.dataset_info[:build_id]
  end

  def test_etag_not_modified_means_unchanged
    stub_release!
    OpenASN.update!

    stub_request(:get, "#{RELEASE}manifest.json")
      .with(headers: { "If-None-Match" => '"m1"' })
      .to_return(status: 304)
    assert_equal :unchanged, OpenASN.update!
  end

  def test_same_build_id_skips_downloads
    stub_release!
    OpenASN.update!

    # Manifest re-served with a new etag but the same build_id: no downloads.
    stub_request(:get, "#{RELEASE}manifest.json")
      .to_return(status: 200, body: @manifest, headers: { "ETag" => '"m2"' })
    assert_equal :unchanged, OpenASN.update!
    # exactly the ONE download from the first update! — webmock counts by
    # URL pattern across the whole test, so times: 1 asserts "no re-download"
    assert_requested(:get, "#{RELEASE}openasn-ipv4.bin", times: 1)
  end

  def test_sha256_mismatch_refuses_install_and_keeps_previous_data
    stub_release!
    OpenASN.update!
    good_v4 = File.binread(File.join(@test_data_dir, "openasn-ipv4.bin"))

    tampered = @manifest.sub(Digest::SHA256.hexdigest(@v4), "0" * 64)
    stub_request(:get, "#{RELEASE}manifest.json")
      .to_return(status: 200, body: tampered.sub("09:00:00", "10:00:00"), headers: { "ETag" => '"m3"' })

    assert_raises(OpenASN::IntegrityError) { OpenASN.update!(force: true) }
    # Previous artifact untouched:
    assert_equal good_v4, File.binread(File.join(@test_data_dir, "openasn-ipv4.bin"))
    assert_equal :residential_isp, OpenASN.lookup("1.0.0.42").verdict
  end

  def test_manifest_fetch_failure_is_quiet_keep_stale_unless_forced
    stub_request(:get, "#{RELEASE}manifest.json").to_return(status: 500)
    assert_equal :unchanged, OpenASN.update!
    assert_raises(OpenASN::UpdateError) { OpenASN.update!(force: true) }
  end

  def test_manifest_missing_required_artifact_raises
    broken = JSON.generate(JSON.parse(@manifest).tap { |m| m["files"].shift }) # drop ipv4
    stub_request(:get, "#{RELEASE}manifest.json")
      .to_return(status: 200, body: broken, headers: { "ETag" => '"m4"' })
    assert_raises(OpenASN::UpdateError) { OpenASN.update!(force: true) }
  end

  def test_concurrent_update_skips_via_lock
    stub_release!
    FileUtils.mkdir_p(@test_data_dir)
    lock = File.open(File.join(@test_data_dir, ".update.lock"), File::RDWR | File::CREAT)
    assert lock.flock(File::LOCK_EX | File::LOCK_NB)
    # This process holds the lock via a separate descriptor… but flock is
    # per-process on the same file: use a subprocess to hold it instead.
    lock.flock(File::LOCK_UN)
    lock.close

    holder = spawn(RbConfig.ruby, "-e", <<~RUBY)
      f = File.open(File.join(#{@test_data_dir.inspect}, ".update.lock"), File::RDWR | File::CREAT)
      f.flock(File::LOCK_EX)
      sleep 5
    RUBY
    sleep 0.4 # let the child grab the lock
    assert_equal :locked, OpenASN.update!
  ensure
    Process.kill("TERM", holder) if holder
    Process.wait(holder) if holder
  end

  def test_pin_version_changes_release_url
    configure { |c| c.pin_version = "2026-07-04" }
    pinned = "https://github.com/openasn/openasn/releases/download/2026-07-04/"
    stub = stub_request(:get, "#{pinned}manifest.json").to_return(status: 500)
    OpenASN.update!
    assert_requested(stub)
  end
end
