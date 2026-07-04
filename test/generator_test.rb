# frozen_string_literal: true

require "test_helper"
require "rails/generators"
require "generators/openasn/install/install_generator"

class GeneratorTest < Minitest::Test
  def setup
    super
    @dest = Dir.mktmpdir("openasn-generator-test")
    FileUtils.mkdir_p(File.join(@dest, "config"))
  end

  def teardown
    FileUtils.remove_entry(@dest) if @dest && Dir.exist?(@dest)
    super
  end

  def run_generator
    capture_io do
      Openasn::Generators::InstallGenerator.start([], destination_root: @dest)
    end
  end

  def test_creates_initializer_with_shadow_mode_guidance
    run_generator
    initializer = File.read(File.join(@dest, "config/initializers/openasn.rb"))
    assert_includes initializer, "OpenASN.configure"
    assert_includes initializer, "Shadow mode"
    assert_includes initializer, "never hard-block"
    # the Rack::Attack example must ship COMMENTED OUT (log-first doctrine)
    assert_includes initializer, "# Rack::Attack.blocklist"
  end

  def test_wires_solid_queue_recurring_yml_when_present
    File.write(File.join(@dest, "config/recurring.yml"), "production:\n  cleanup:\n    class: CleanupJob\n")
    run_generator
    recurring = File.read(File.join(@dest, "config/recurring.yml"))
    assert_includes recurring, "OpenASN::UpdateJob"
    assert_includes recurring, "4:12am UTC"

    # idempotent: running again must not duplicate the entry
    run_generator
    recurring = File.read(File.join(@dest, "config/recurring.yml"))
    assert_equal 1, recurring.scan("OpenASN::UpdateJob").count
  end

  def test_skips_recurring_wiring_gracefully_without_solid_queue
    run_generator
    refute File.exist?(File.join(@dest, "config/recurring.yml"))
  end
end
