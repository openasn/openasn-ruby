# frozen_string_literal: true

require "json"
require "socket"
require "thread"
require "timeout"

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
    DEFAULT_DNS_THREADS = 16
    MAX_DNS_THREADS = 32
    DNS_TIMEOUT_SECONDS = 4

    class << self
      attr_accessor :dns_resolver
    end
    self.dns_resolver = lambda do |hostname|
      Socket.getaddrinfo(hostname, nil, Socket::AF_UNSPEC, Socket::SOCK_STREAM).map { |entry| entry[3] }.uniq
    end

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
        response = fetch_source_url(source, url, etag)
        if response == :not_modified
          not_modified = true
          break
        end
        new_etag = response.etag if urls.length == 1
        tokens.concat(Parsers.parse(source["parser"], response.body))
      end
      tokens = resolve_hostnames(tokens, source)

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

    def fetch_source_url(source, url, etag)
      if source["method"].to_s.upcase == "POST"
        @http.post_form(url, source["form"] || {})
      else
        @http.get(url, etag: etag)
      end
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
      urls.concat(source["urls"]) if source["urls"].is_a?(Array)
      urls << source["url_ipv6"] if source["url_ipv6"]
      urls
    end

    def resolve_hostnames(tokens, source)
      return tokens unless source["resolve_hostnames"]

      direct = []
      hosts = []
      tokens.each do |token|
        token = token.to_s.strip
        next if token.empty?

        if CidrUtils.parse(token)
          direct << token
        elsif hostname?(token)
          hosts << token.downcase
        end
      end
      hosts.uniq!
      return direct if hosts.empty?

      resolved = resolve_hosts(hosts, source)
      @logger.info("openasn: tier B #{source['id']}: resolved #{resolved.length} IPs from #{hosts.length} hostnames")
      direct + resolved
    end

    def resolve_hosts(hosts, source)
      threads = [[source["dns_threads"] || DEFAULT_DNS_THREADS, MAX_DNS_THREADS].min, hosts.length].min
      queue = Queue.new
      hosts.each { |host| queue << host }
      resolved = []
      mutex = Mutex.new

      workers = threads.times.map do
        Thread.new do
          loop do
            host = queue.pop(true)
            ips = Timeout.timeout(DNS_TIMEOUT_SECONDS) { self.class.dns_resolver.call(host) }
            mutex.synchronize { resolved.concat(ips) }
          rescue ThreadError
            break
          rescue StandardError
            next
          end
        end
      end
      workers.each(&:join)
      resolved.uniq
    end

    def hostname?(token)
      token.match?(/\A(?=.{1,253}\z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\z/i)
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
