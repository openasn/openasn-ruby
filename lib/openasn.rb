# frozen_string_literal: true

# stdlib only (zero-dependency contract). "time" is load-bearing: it
# provides Time.parse / Time.iso8601 / Time#iso8601 used across the
# updater, overlay store, and staleness probes — do not assume another
# library loaded it (bare non-Rails processes won't have it).
require "time"

require_relative "openasn/version"
require_relative "openasn/errors"
require_relative "openasn/ip"
require_relative "openasn/binary_format"
require_relative "openasn/special_ranges"
require_relative "openasn/configuration"
require_relative "openasn/result"
require_relative "openasn/overlay_store"
require_relative "openasn/snapshot"
require_relative "openasn/classifier"
require_relative "openasn/dataset"
require_relative "openasn/http_client"
require_relative "openasn/cidr_utils"
require_relative "openasn/parsers"
require_relative "openasn/tier_b"
require_relative "openasn/updater"
require_relative "openasn/middleware"
require_relative "openasn/railtie" if defined?(Rails::Railtie)

# OpenASN — offline IP origin intelligence.
#
#   OpenASN.lookup("203.0.113.42")
#   # => #<OpenASN::Result 203.0.113.42 verdict=unknown …>
#
#   r = OpenASN.lookup(request.remote_ip)
#   r.verdict          # :residential_isp | :mobile | :business | :hosting |
#                      # :vpn | :tor_exit | :relay | :enterprise_gateway |
#                      # :education | :government | :cgnat | :private | :unknown
#   r.infrastructure?  # verdict in {hosting, vpn, tor_exit} — the honest boolean
#   r.likely_human?    # verdict in {residential_isp, mobile, relay, cgnat, enterprise_gateway}
#   r.asn / r.as_org / r.category / r.network_role / r.provider / r.sources
#
# Every lookup is local (microseconds, no network). Data ships as a bundled
# seed and refreshes from OpenASN's nightly releases + Tier B authorities
# via OpenASN.update! / OpenASN::UpdateJob.
#
# REMEMBER WHAT VERDICTS MEAN: a clean/`residential_isp` verdict is absence
# of evidence, NOT proof of innocence — residential proxies are invisible
# to any offline dataset. `vpn`/`hosting`/`tor_exit` are high-confidence;
# treat everything else as a signal, not a sentence. Never hard-block
# `relay`, `cgnat`, or `mobile`: those are real people.
module OpenASN
  class << self
    def configuration
      @configuration ||= Configuration.new
    end

    def configure
      yield(configuration)
      # Config affects how snapshots load (data_dir, memory_mode, tier_b…):
      # drop any snapshot built under the old config. Cheap; lazy reload.
      @dataset = nil
    end

    def dataset
      @dataset ||= Dataset.new(configuration)
    end

    # Classify an IP (String or IPAddr). Never returns nil; raises
    # OpenASN::InvalidIPError (an ArgumentError) on unparseable input.
    def lookup(ip)
      Classifier.classify(dataset.snapshot, ip)
    end
    alias check lookup
    alias [] lookup

    # Like lookup, but returns nil on nil/blank/unparseable input instead of
    # raising — for analytics and rendering call sites where a missing or
    # garbage IP is ordinary data (an old DB row, a stripped header), not an
    # exceptional condition worth a begin/rescue at every call site.
    def try_lookup(ip)
      return nil if ip.nil? || (ip.is_a?(String) && ip.strip.empty?)

      lookup(ip)
    rescue InvalidIPError
      nil
    end

    # Refresh canonical artifacts + Tier B overlays now, atomically
    # swapping the in-memory dataset on success.
    # -> :updated | :tier_b_only | :unchanged | :locked
    def update!(force: false)
      Updater.new(configuration, dataset).run(force: force)
    end

    # Load the dataset at boot instead of on first lookup (call from an
    # initializer in latency-sensitive apps; first lazy load costs ~50-200ms
    # depending on memory_mode).
    def eager_load!
      dataset.eager_load!
    end

    def dataset_info
      dataset.info
    end

    # Cheap "is the on-disk data old?" probe that does NOT load the
    # dataset. Considers the freshest of data_dir and the bundled seed
    # (used by the Railtie's boot staleness check).
    def data_stale_on_disk?(max_age: Dataset::STALE_AFTER)
      build_ids = [File.join(configuration.data_dir, "manifest.json"),
                   File.join(Snapshot::SEED_DIR, "manifest.json")].filter_map do |path|
        next unless File.exist?(path)

        JSON.parse(File.read(path))["build_id"]
      rescue JSON::ParserError
        nil
      end
      newest = build_ids.filter_map { |id| Time.iso8601(id) rescue nil }.max # rubocop:disable Style/RescueModifier
      newest.nil? || (Time.now - newest) > max_age
    end

    # Test/console helper: forget configuration and loaded data.
    def reset!
      @configuration = nil
      @dataset = nil
    end
  end
end
