# frozen_string_literal: true

module OpenASN
  class Railtie < Rails::Railtie
    # Make OpenASN::UpdateJob exist as soon as ActiveJob does.
    initializer "openasn.update_job" do
      ActiveSupport.on_load(:active_job) { require "openasn/update_job" }
    end

    # Opportunistic staleness check (PRD behavior): if the newest data on
    # disk is older than a week and auto_update is on, enqueue a refresh.
    # Uses a cheap file probe — it must NOT force the dataset to load at
    # boot (lazy-load is the contract; eager_load! is opt-in). Deliberately
    # skipped in test env, deliberately best-effort: a broken queue must
    # never break boot.
    config.after_initialize do
      next if Rails.env.test?
      next unless OpenASN.configuration.auto_update

      begin
        if OpenASN.data_stale_on_disk? && defined?(OpenASN::UpdateJob)
          OpenASN::UpdateJob.perform_later
          OpenASN.configuration.logger.info("openasn: dataset older than 7 days — background refresh enqueued")
        end
      rescue StandardError => e
        OpenASN.configuration.logger.warn("openasn: boot staleness check skipped (#{e.message})")
      end
    end
  end
end
