# frozen_string_literal: true

module OpenASN
  # Owns the live Snapshot and its lifecycle. Concurrency model (the whole
  # point of this class — do not "simplify" it):
  #
  #   * Readers call #snapshot and get whatever is current. The swap is a
  #     single ivar assignment — atomic under MRI's GVL — so readers see
  #     either the old complete snapshot or the new complete snapshot,
  #     never partial state. No locks on the read path, ever.
  #   * The lazy first load and explicit reloads are serialized with a
  #     Mutex so N threads arriving on a cold process build one snapshot,
  #     not N.
  #   * Multi-process reality (puma workers): the updater process writes
  #     new files atomically; OTHER processes notice via a cheap periodic
  #     freshness probe (#maybe_reload_from_disk — a File.mtime call at
  #     most every RELOAD_CHECK_INTERVAL seconds, amortized to ~zero) and
  #     rebuild their in-memory snapshot from disk.
  class Dataset
    RELOAD_CHECK_INTERVAL = 300 # seconds
    STALE_AFTER = 7 * 86_400    # boot-time "kick a refresh" threshold (documented in README "Updates")

    def initialize(config)
      @config = config
      @snapshot = nil
      @load_mutex = Mutex.new
      @last_disk_check = 0.0
      @loaded_manifest_mtime = nil
    end

    def snapshot
      snap = @snapshot
      return snap if snap && !disk_check_due?

      snap ? maybe_reload_from_disk : load!
    end

    def eager_load!
      load!
      nil
    end

    # Called by the updater after it wrote new files: rebuild + swap now.
    def reload!
      @load_mutex.synchronize do
        @snapshot = Snapshot.build(@config)
        @loaded_manifest_mtime = manifest_mtime
        @last_disk_check = monotonic_now
        @snapshot
      end
    end

    def loaded? = !@snapshot.nil?

    def stale?
      snap = snapshot
      snap.age_seconds > STALE_AFTER
    end

    def info
      snap = snapshot
      {
        build_id: snap.build_id,
        built_at: Time.at(snap.build_ts).utc,
        loaded_at: snap.loaded_at,
        origin: snap.origin,
        memory_mode: @config.memory_mode,
        records: snap.record_counts,
        tier_b_status: snap.tier_b_status
      }
    end

    private

    def load!
      @load_mutex.synchronize do
        # Another thread may have loaded while we waited on the mutex.
        return @snapshot if @snapshot && !disk_check_due?

        @snapshot = Snapshot.build(@config)
        @loaded_manifest_mtime = manifest_mtime
        @last_disk_check = monotonic_now
        @snapshot
      end
    end

    def disk_check_due?
      monotonic_now - @last_disk_check > RELOAD_CHECK_INTERVAL
    end

    # Cheap cross-process freshness: compare the on-disk manifest mtime to
    # what this process loaded. Runs at most once per RELOAD_CHECK_INTERVAL
    # per process; costs one stat() when it does.
    def maybe_reload_from_disk
      @load_mutex.synchronize do
        @last_disk_check = monotonic_now
        current = manifest_mtime
        if current != @loaded_manifest_mtime
          @config.logger.info("openasn: dataset changed on disk — reloading")
          @snapshot = Snapshot.build(@config)
          @loaded_manifest_mtime = current
        end
        @snapshot
      end
    rescue StandardError => e
      @config.logger.warn("openasn: reload check failed (#{e.message}); keeping current snapshot")
      @snapshot
    end

    def manifest_mtime
      path = File.join(@config.data_dir, "manifest.json")
      File.exist?(path) ? File.mtime(path) : nil
    end

    def monotonic_now = Process.clock_gettime(Process::CLOCK_MONOTONIC)
  end
end
