# frozen_string_literal: true

# Defined only when ActiveJob is available (required from the Railtie, or
# require it yourself in non-Rails ActiveJob apps AFTER loading ActiveJob).
#
# Scheduling is app-side — with Solid Queue (Rails 8 default), in
# config/recurring.yml:
#
#   production:
#     openasn_update:
#       class: OpenASN::UpdateJob
#       schedule: every day at 4:12am UTC   # off-hour on purpose: be kind
#                                           # to the volunteer-run upstreams
#
# (The install generator wires this for you.) Data freshness NEVER flows
# through gem releases — this job is the only moving part.
if defined?(ActiveJob::Base)
  module OpenASN
    class UpdateJob < ActiveJob::Base
      queue_as :default

      # Transient network trouble self-heals on the next run; a persistent
      # failure surfaces via logs + dataset_info staleness, not via a
      # crashed-job pile-up.
      retry_on OpenASN::UpdateError, wait: 5.minutes, attempts: 3

      def perform(force: false)
        OpenASN.update!(force: force)
      end
    end
  end
end
