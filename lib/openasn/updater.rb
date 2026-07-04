# frozen_string_literal: true

require "digest"
require "fileutils"
require "json"

module OpenASN
  # The data refresh cycle (what OpenASN.update! / UpdateJob runs):
  #
  #   1. Canonical: GET {release_url}manifest.json (ETag-conditional).
  #      When it changed, download each artifact, VERIFY ITS SHA-256
  #      against the manifest, write to *.tmp, File.rename into place
  #      (atomic on POSIX — a crashed update can never leave a torn file),
  #      then write manifest.json LAST — it is the commit marker other
  #      processes watch for (Dataset#maybe_reload_from_disk).
  #   2. Tier B: execute the fetch-manifest for enabled sources (TierB).
  #      Per-source failures keep stale data and never fail the update.
  #   3. Swap the in-process snapshot.
  #
  # Concurrency: a non-blocking flock serializes updaters across processes
  # (first puma worker wins; the rest skip — they'll pick up the files via
  # the freshness probe). Never raises for "someone else is updating".
  class Updater
    CANONICAL_FILES = %w[openasn-ipv4.bin openasn-ipv6.bin openasn-orgs.bin].freeze

    def initialize(config, dataset)
      @config = config
      @dataset = dataset
      @http = HttpClient.new(user_agent: config.user_agent, logger: config.logger)
      @logger = config.logger
    end

    # -> :updated | :tier_b_only | :unchanged | :locked
    def run(force: false)
      FileUtils.mkdir_p(@config.data_dir)
      with_lock do
        canonical_changed = refresh_canonical(force: force)
        tier_b_changed = TierB.new(@config, @http).execute(force: force)

        if canonical_changed || tier_b_changed
          @dataset.reload!
          notify(canonical_changed ? :updated : :tier_b_only)
          canonical_changed ? :updated : :tier_b_only
        else
          :unchanged
        end
      end
    end

    private

    def refresh_canonical(force:)
      state = read_state
      begin
        response = @http.get("#{@config.release_url}manifest.json",
                             etag: force ? nil : state["manifest_etag"])
      rescue StandardError => e
        # No manifest, no update — but never crash the job: keep-last-good
        # is the contract (the seed or previous download keeps serving).
        raise UpdateError, "could not fetch manifest: #{e.message}" if force

        @logger.warn("openasn: manifest fetch failed (#{e.message}); keeping current data")
        return false
      end
      return false if response == :not_modified

      manifest = JSON.parse(response.body)
      if !force && manifest["build_id"] && manifest["build_id"] == current_local_build_id
        # Same build re-served (ETag miss, mirror change…): record the new
        # ETag, skip the downloads.
        write_state(state.merge("manifest_etag" => response.etag))
        return false
      end

      by_name = (manifest["files"] || []).to_h { |f| [f["name"], f] }
      downloads = CANONICAL_FILES.filter_map do |name|
        meta = by_name[name]
        # Manifest without a required artifact = upstream problem; orgs is
        # optional richness, the .bin artifacts are not.
        if meta.nil?
          raise UpdateError, "release manifest is missing #{name}" unless name == "openasn-orgs.bin"

          next
        end
        [name, meta]
      end

      # Two-phase install: download + verify EVERYTHING first, then rename
      # all files in one tight loop. A crash mid-download therefore can't
      # leave a mixed set (new ipv4 + old ipv6) on disk; renames are so
      # close together that the mixed window is effectively gone.
      verified = downloads.map do |(name, meta)|
        body = @http.get("#{@config.release_url}#{name}").body
        actual = Digest::SHA256.hexdigest(body)
        unless actual == meta["sha256"]
          raise IntegrityError,
                "#{name} SHA-256 mismatch (expected #{meta['sha256'][0, 12]}…, got #{actual[0, 12]}…) — " \
                "refusing to install; previous data stays live"
        end

        tmp = File.join(@config.data_dir, "#{name}.tmp")
        File.binwrite(tmp, body)
        [tmp, File.join(@config.data_dir, name)]
      end
      verified.each { |(tmp, final)| File.rename(tmp, final) }

      # Also mirror the fetch-manifest so Tier B follows the release's
      # current source list (falls back to the bundled copy when absent).
      begin
        fm = @http.get("#{@config.release_url}fetch-manifest.json").body
        JSON.parse(fm) # only install valid JSON
        tmp = File.join(@config.data_dir, "fetch-manifest.json.tmp")
        File.write(tmp, fm)
        File.rename(tmp, File.join(@config.data_dir, "fetch-manifest.json"))
      rescue StandardError => e
        @logger.warn("openasn: fetch-manifest refresh failed (#{e.message}); using previous/bundled copy")
      end

      # Commit marker LAST: other processes treat manifest.json's mtime as
      # "new data is fully in place".
      tmp = File.join(@config.data_dir, "manifest.json.tmp")
      File.write(tmp, response.body)
      File.rename(tmp, File.join(@config.data_dir, "manifest.json"))

      write_state(read_state.merge("manifest_etag" => response.etag,
                                   "updated_at" => Time.now.utc.iso8601))
      @logger.info("openasn: canonical data updated to build #{manifest['build_id']}")
      true
    end

    def current_local_build_id
      path = File.join(@config.data_dir, "manifest.json")
      return nil unless File.exist?(path)

      JSON.parse(File.read(path))["build_id"]
    rescue JSON::ParserError
      nil
    end

    def read_state
      path = File.join(@config.data_dir, "update-state.json")
      File.exist?(path) ? JSON.parse(File.read(path)) : {}
    rescue JSON::ParserError
      {}
    end

    def write_state(state)
      path = File.join(@config.data_dir, "update-state.json")
      File.write("#{path}.tmp", JSON.pretty_generate(state))
      File.rename("#{path}.tmp", path)
    end

    def with_lock
      lock_path = File.join(@config.data_dir, ".update.lock")
      File.open(lock_path, File::RDWR | File::CREAT, 0o644) do |f|
        unless f.flock(File::LOCK_EX | File::LOCK_NB)
          @logger.info("openasn: another process is updating — skipping")
          return :locked
        end
        yield
      end
    end

    def notify(kind)
      return unless defined?(ActiveSupport::Notifications)

      ActiveSupport::Notifications.instrument("openasn.updated", kind: kind,
                                                                 info: @dataset.info)
    rescue StandardError => e
      @logger.warn("openasn: notification hook failed (#{e.message})")
    end
  end
end
