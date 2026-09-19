# frozen_string_literal: true

require "test_helper"

# The HTTP client is the gem's only outbound edge. Tier B sources are remote
# parties we do not control, so a hostile or compromised one must not be able
# to steer a fetch off http/https (`Location: file:///…` would otherwise make
# the "download" read a local file on the host running the gem).
class HttpClientTest < Minitest::Test
  def setup
    super
    @logger = Logger.new(File::NULL)
    @client = OpenASN::HttpClient.new(user_agent: "openasn-test", logger: @logger)
  end

  # --- the security fix -----------------------------------------------------

  def test_refuses_a_file_scheme_redirect_target
    secret = File.join(@test_data_dir, "secret.txt")
    File.write(secret, "TOP SECRET LOCAL FILE")
    stub_request(:get, "https://source.example/list.txt")
      .to_return(status: 302, headers: { "Location" => "file://#{secret}" })

    error = assert_raises(OpenASN::UpdateError) { @client.get("https://source.example/list.txt") }

    assert_match(/non-http\(s\)/, error.message)
    assert_match(/file/, error.message)
    refute_match(/TOP SECRET/, error.message)
  end

  def test_refuses_a_bare_file_root_redirect_target
    stub_request(:get, "https://source.example/list.txt")
      .to_return(status: 302, headers: { "Location" => "file:///etc/passwd" })

    error = assert_raises(OpenASN::UpdateError) { @client.get("https://source.example/list.txt") }
    assert_match(/non-http\(s\)/, error.message)
  end

  def test_refuses_other_non_http_redirect_schemes
    { "ftp://ftp.example/pub/x" => "ftp",
      "data:text/plain,pwned" => "data",
      "javascript:alert(1)" => "javascript",
      "gopher://g.example/1" => "gopher" }.each do |location, scheme|
      WebMock.reset!
      stub_request(:get, "https://source.example/list.txt")
        .to_return(status: 302, headers: { "Location" => location })

      error = assert_raises(OpenASN::UpdateError) { @client.get("https://source.example/list.txt") }
      assert_match(/non-http\(s\)/, error.message, "#{scheme} redirect was not refused")
    end
  end

  def test_refuses_a_non_http_scheme_on_the_second_hop
    stub_request(:get, "https://source.example/a")
      .to_return(status: 302, headers: { "Location" => "https://cdn.example/b" })
    stub_request(:get, "https://cdn.example/b")
      .to_return(status: 302, headers: { "Location" => "file:///etc/passwd" })

    error = assert_raises(OpenASN::UpdateError) { @client.get("https://source.example/a") }
    assert_match(/non-http\(s\)/, error.message)
    assert_requested :get, "https://cdn.example/b", times: 1
  end

  def test_refuses_a_non_http_url_from_the_caller
    error = assert_raises(OpenASN::UpdateError) { @client.get("file:///etc/passwd") }
    assert_match(/refusing non-http\(s\) URL/, error.message)
  end

  def test_refuses_a_post_form_redirect_to_a_non_http_scheme
    stub_request(:post, "https://vpn.example/api").to_return(
      status: 307, headers: { "Location" => "file:///etc/passwd" }
    )

    error = assert_raises(OpenASN::UpdateError) { @client.post_form("https://vpn.example/api", { a: "1" }) }
    assert_match(/non-http\(s\)/, error.message)
  end

  def test_refuses_a_hostless_http_redirect_target
    stub_request(:get, "https://source.example/list.txt")
      .to_return(status: 302, headers: { "Location" => "http:///nowhere" })

    error = assert_raises(OpenASN::UpdateError) { @client.get("https://source.example/list.txt") }
    assert_match(/host/, error.message)
  end

  # --- regression guards: the legitimate redirect paths still work ----------

  def test_still_follows_a_cross_host_https_redirect
    stub_request(:get, "https://github.example/releases/download/latest/openasn-ipv4.bin")
      .to_return(status: 302, headers: { "Location" => "https://objects.example/signed?token=1" })
    stub_request(:get, "https://objects.example/signed?token=1")
      .to_return(status: 200, body: "ARTIFACT", headers: { "ETag" => '"e1"' })

    response = @client.get("https://github.example/releases/download/latest/openasn-ipv4.bin")

    assert_equal "ARTIFACT", response.body
    assert_equal '"e1"', response.etag
  end

  def test_still_follows_a_relative_redirect
    stub_request(:get, "https://source.example/a/list.txt")
      .to_return(status: 301, headers: { "Location" => "/v2/list.txt" })
    stub_request(:get, "https://source.example/v2/list.txt").to_return(status: 200, body: "OK")

    assert_equal "OK", @client.get("https://source.example/a/list.txt").body
  end

  def test_still_follows_a_protocol_relative_redirect_inheriting_https
    stub_request(:get, "https://source.example/list.txt")
      .to_return(status: 302, headers: { "Location" => "//mirror.example/list.txt" })
    stub_request(:get, "https://mirror.example/list.txt").to_return(status: 200, body: "OK")

    assert_equal "OK", @client.get("https://source.example/list.txt").body
  end

  def test_http_to_https_upgrade_redirect_is_allowed
    stub_request(:get, "http://source.example/list.txt")
      .to_return(status: 301, headers: { "Location" => "https://source.example/list.txt" })
    stub_request(:get, "https://source.example/list.txt").to_return(status: 200, body: "OK")

    assert_equal "OK", @client.get("http://source.example/list.txt").body
  end

  def test_https_to_http_downgrade_is_followed_but_logged
    logged = []
    logger = Object.new
    logger.define_singleton_method(:warn) { |message| logged << message }
    logger.define_singleton_method(:info) { |_message| nil }
    client = OpenASN::HttpClient.new(user_agent: "openasn-test", logger: logger)

    stub_request(:get, "https://source.example/list.txt")
      .to_return(status: 302, headers: { "Location" => "http://legacy.example/list.txt" })
    stub_request(:get, "http://legacy.example/list.txt").to_return(status: 200, body: "OK")

    assert_equal "OK", client.get("https://source.example/list.txt").body
    assert_equal 1, logged.length
    assert_match(/plaintext/, logged.first)
  end

  def test_304_is_not_treated_as_a_redirect
    stub_request(:get, "https://source.example/list.txt").to_return(status: 304)

    assert_equal :not_modified, @client.get("https://source.example/list.txt", etag: '"e1"')
  end

  def test_redirect_loop_is_bounded
    stub_request(:get, "https://source.example/loop")
      .to_return(status: 302, headers: { "Location" => "https://source.example/loop" })

    error = assert_raises(OpenASN::UpdateError) { @client.get("https://source.example/loop") }
    assert_match(/too many redirects/, error.message)
  end
end
