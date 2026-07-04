# frozen_string_literal: true

require "json"

module OpenASN
  # Executes fetch-manifest.json: pulls each enabled Tier B source from its
  # ORIGINAL authority (Apple, the Tor Project, AWS…), parses, merges, and
  # packs it into the local overlay store.
  #
  # Prime directives (each encodes a production lesson):
  #   * Per-source isolation: one source failing NEVER touches the others
  #     and NEVER raises out of the executor. Failures keep last-good data
  #     ("keep_stale") and are recorded in state.json — visible via
  #     OpenASN.dataset_info[:tier_b_status].
  #   * Honor cadence_hours: a 12h source isn't refetched on every deploy's
  #     update run. `force: true` overrides (manual OpenASN.update!(force:)).
  #   * Unknown source ids / parser ids are skipped with a warning — old
  #     gem versions must survive fetch-manifest evolution.
  #   * Every request carries the descriptive User-Agent. These are mostly
  #     free/volunteer endpoints; being a good citizen is part of the deal.
  class TierB
    def initialize(config, http)
      @config = config
      @http = http
      @logger = config.logger
      @store = OverlayStore.new(config.data_dir)
    end

    # -> true when any overlay changed (snapshot reload needed)
    def execute(force: false)
      manifest = load_manifest
      return false unless manifest

      enabled = @config.enabled_tier_b_source_ids
      changed = false
      (manifest["sources"] || []).each do |source|
        id = source["id"]
        next unless enabled.include?(id)

        unless Parsers.known?(source["parser"])
          @logger.warn("openasn: tier B source #{id} uses unknown parser #{source['parser'].inspect} — " \
                       "skipping (update the openasn gem to pick it up)")
          next
        end

        changed |= refresh_source(source, force: force)
      end
      changed
    end

    private

    # Freshest available manifest: data_dir (mirrored on canonical update)
    # -> bundled copy from gem release time.
    def load_manifest
      [File.join(@config.data_dir, "fetch-manifest.json"),
       File.join(Snapshot::SEED_DIR, "fetch-manifest.json")].each do |path|
        next unless File.exist?(path)

        return JSON.parse(File.read(path))
      rescue JSON::ParserError => e
        @logger.warn("openasn: unreadable fetch-manifest at #{path} (#{e.message})")
      end
      nil
    end

    def refresh_source(source, force:)
      id = source["id"]
      unless force || due?(id, source["cadence_hours"])
        return false
      end

      urls = resolve_urls(source)
      if urls.empty?
        @store.record_failure(id, "could not resolve source URL")
        return false
      end

      etag = urls.length == 1 && !force ? @store.source_state(id)["etag"] : nil
      tokens = []
      new_etag = nil
      not_modified = false

      urls.each do |url|
        response = @http.get(url, etag: etag)
        if response == :not_modified
          not_modified = true
          break
        end
        new_etag = response.etag if urls.length == 1
        tokens.concat(Parsers.parse(source["parser"], response.body))
      end

      if not_modified
        @store.record_fresh(id)
        return false
      end

      ranges = CidrUtils.ranges_by_family(tokens)
      total = ranges[:ipv4].length + ranges[:ipv6].length
      if total.zero?
        # An empty security list is far more likely upstream breakage than
        # reality — keep whatever we had (keep_stale), record loudly.
        @store.record_failure(id, "parsed 0 ranges — upstream format changed? keeping stale data")
        return false
      end

      @store.write(id, maps_to: source["maps_to"], provider: source["provider"],
                       etag: new_etag, ranges_by_family: ranges)
      @logger.info("openasn: tier B #{id}: #{ranges[:ipv4].length} v4 + #{ranges[:ipv6].length} v6 ranges")
      true
    rescue StandardError => e
      # keep_stale: failure is recorded, previous overlay files stay live.
      @store.record_failure(id, "#{e.class}: #{e.message}")
      @logger.warn("openasn: tier B #{id} failed (#{e.message}); keeping stale data")
      false
    end

    def due?(id, cadence_hours)
      last = @store.fetched_at(id)
      return true unless last

      (Time.now - last) >= (cadence_hours || 24) * 3600 * 0.99 # 1% slack so daily jobs don't skip-drift
    end

    def resolve_urls(source)
      urls = []
      if source["resolver"] == "azure_download_page"
        url = resolve_azure(source["page_url"])
        urls << url if url
      elsif source["url"]
        urls << source["url"]
      end
      urls << source["url_ipv6"] if source["url_ipv6"]
      urls
    end

    # Azure's actual JSON URL rotates weekly behind the download page.
    # Scrape it; on any failure return nil (-> keep stale, try tomorrow).
    def resolve_azure(page_url)
      html = @http.get(page_url).body
      html[%r{https://download\.microsoft\.com/download/[^"'\s]+ServiceTags_Public_\d+\.json}]
    rescue StandardError => e
      @logger.warn("openasn: azure page resolution failed (#{e.message})")
      nil
    end
  end
end
