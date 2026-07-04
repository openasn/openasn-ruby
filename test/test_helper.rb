# frozen_string_literal: true

require "simplecov"

$LOAD_PATH.unshift File.expand_path("../lib", __dir__)

require "openasn"
require "minitest/autorun"
require "minitest/reporters"
require "mocha/minitest"
require "webmock/minitest"
require "tmpdir"
require "fileutils"

Minitest::Reporters.use! Minitest::Reporters::SpecReporter.new

# No real HTTP in tests, ever.
WebMock.disable_net_connect!(allow_localhost: true)

Dir[File.expand_path("support/**/*.rb", __dir__)].each { |f| require f }

class Minitest::Test
  # Every test gets a pristine OpenASN and its own data_dir.
  def setup
    OpenASN.reset!
    @test_data_dir = Dir.mktmpdir("openasn-test")
    OpenASN.configure { |c| c.data_dir = @test_data_dir }
  end

  def teardown
    FileUtils.remove_entry(@test_data_dir) if @test_data_dir && Dir.exist?(@test_data_dir)
    OpenASN.reset!
    # Defining #teardown here clobbers webmock/minitest's aliased teardown
    # chain, so its automatic reset never runs — without this line, stub
    # request COUNTERS accumulate across tests and every assert_requested
    # with a count becomes order-dependent. Keep it explicit.
    WebMock.reset!
  end

  def configure(&block)
    OpenASN.configure(&block)
  end
end
