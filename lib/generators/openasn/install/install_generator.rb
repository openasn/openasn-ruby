# frozen_string_literal: true

require "rails/generators/base"

module Openasn
  module Generators
    # rails generate openasn:install
    #
    # Creates the initializer and wires the daily update job into Solid
    # Queue's recurring.yml when present. No migrations — OpenASN is
    # file-based by design (storage/openasn/), nothing touches your DB.
    class InstallGenerator < Rails::Generators::Base
      source_root File.expand_path("templates", __dir__)

      RECURRING_JOB = <<~YAML
        # Added by `rails g openasn:install` — daily IP-origin data refresh
        openasn_update:
          class: OpenASN::UpdateJob
          queue: default
          schedule: every day at 4:12am UTC
      YAML

      def create_initializer
        template "openasn.rb", "config/initializers/openasn.rb"
      end

      def wire_recurring_job
        recurring = "config/recurring.yml"
        unless File.exist?(File.expand_path(recurring, destination_root))
          say_status :skipped, "#{recurring} not found — schedule OpenASN::UpdateJob with your own scheduler (see README)", :yellow
          return
        end

        if File.read(File.expand_path(recurring, destination_root)).include?("OpenASN::UpdateJob")
          say_status :identical, "#{recurring} already schedules OpenASN::UpdateJob", :blue
          return
        end

        # 4:12am UTC: after the nightly data build (03:17 UTC) completes,
        # off-hour to be kind to the Tier B upstreams.
        recurring_path = File.expand_path(recurring, destination_root)
        File.write(recurring_path, recurring_with_openasn_job(File.read(recurring_path)))
      end

      def display_post_install_message
        say ""
        say "\tThe `openasn` gem has been successfully installed!", :green
        say ""
        say "OpenASN works out of the box: a data seed is bundled with the gem and"
        say "refreshes itself daily via OpenASN::UpdateJob (data flows through GitHub"
        say "Releases — never through gem updates)."
        say ""
        say "To complete the setup:"
        say "  1. Review config/initializers/openasn.rb (defaults are production-ready)."
        say "  2. Make sure a queue backend runs OpenASN::UpdateJob daily (done for you"
        say "     if you use Solid Queue's recurring.yml)."
        say "  3. Start in SHADOW MODE — log verdicts, block nothing:"
        say ""
        say "       # e.g. in your signups controller:"
        say "       Rails.logger.info(openasn: OpenASN.lookup(request.remote_ip).to_h)"
        say ""
        say "     After a week or two of data, decide your own thresholds. Remember:"
        say "     a residential verdict is absence of evidence, not proof of innocence,"
        say "     and :relay/:cgnat/:mobile are real humans — never hard-block them.", :yellow
        say ""
      end

      private

      def recurring_with_openasn_job(contents)
        production = contents.match(/^production:\s*$/)
        return "#{contents.rstrip}\n\nproduction:\n#{indent(RECURRING_JOB, 2)}" unless production

        insert_at = next_environment_index(contents, production.end(0)) || contents.length
        "#{contents[0...insert_at].rstrip}\n\n#{indent(RECURRING_JOB, 2)}#{contents[insert_at..]}"
      end

      def next_environment_index(contents, offset)
        tail = contents[offset..]
        match = tail.match(/\n(?=\S[^:\n]*:\s*$)/)
        match && offset + match.begin(0)
      end

      def indent(text, spaces)
        prefix = " " * spaces
        text.lines.map { |line| line == "\n" ? line : "#{prefix}#{line}" }.join
      end
    end
  end
end
