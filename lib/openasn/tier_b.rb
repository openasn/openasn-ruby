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

    # --- IANA special-purpose ("bogon") filter -------------------------------
    #
    # A Tier B source is a REMOTE PARTY this project does not control, and a
    # mistake in one of their files becomes a verdict in ours. Live audit
    # 2026-09-12: Vultr's RFC 8805 geofeed (https://geofeed.constant.com/,
    # recipe `vultr`, maps_to hosting) publishes 192.0.2.0/24,
    # 198.51.100.0/24, 203.0.113.0/24, 2001:2::/48, 2001:10::/28,
    # 2001:db8::/32 and 2002::/16 as its own space. `clouds` is ON by default,
    # so every client with Tier B enabled was classifying the RFC 5737 test
    # networks, the RFC 3849 documentation prefix and ALL of 6to4 as
    # hosting/vultr. 2002::/16 is the bad one: a 6to4 address embeds a real
    # end user's IPv4 address, so a residential visitor over 6to4 was being
    # reported as a Vultr datacenter. Twenty-one other sources were clean.
    #
    # So every Tier B overlay is clipped against the non-globally-reachable
    # entries of the IANA IPv4/IPv6 Special-Purpose Address Registries after
    # parsing, for every source. This is Tier B ONLY — the canonical Tier A
    # artifacts are built by this project, not by a third party describing
    # itself.
    #
    # DELIBERATELY NOT FILTERED, because IANA marks them Globally Reachable
    # and an operator may legitimately announce them: 64:ff9b::/96 (the NAT64
    # well-known prefix; its local-use sibling 64:ff9b:1::/48 IS filtered),
    # 192.31.196.0/24 (AS112-v4), 192.52.193.0/24 (AMT, RFC 7450),
    # 192.175.48.0/24 and 2620:4f:8000::/48 (AS112 direct delegation).
    #
    # Accepted collateral, stated plainly: the 2001::/23 container also sweeps
    # up 2001:1::1/128 (PCP anycast), 2001:1::2/128 (TURN), 2001:1::3/128
    # (DNS-SD), 2001:4:112::/48 (AS112-v6), 2001:20::/28 (ORCHIDv2) and
    # 2001:30::/28 (Drone Remote ID), which IANA marks globally reachable.
    # None is customer or egress space and none has ever appeared in a Tier B
    # publication, so the coarser container is the better trade.
    #
    # Kept byte-for-byte in step with the Python client's BOGON_CIDRS
    # (openasn-python src/openasn/tier_b.py) — the two lists are a
    # cross-language contract, so add to both or neither.
    BOGON_CIDRS = %w[
      0.0.0.0/8
      10.0.0.0/8
      100.64.0.0/10
      127.0.0.0/8
      169.254.0.0/16
      172.16.0.0/12
      192.0.0.0/24
      192.0.2.0/24
      192.88.99.0/24
      192.168.0.0/16
      198.18.0.0/15
      198.51.100.0/24
      203.0.113.0/24
      224.0.0.0/4
      240.0.0.0/4
      ::/128
      ::1/128
      ::ffff:0:0/96
      64:ff9b:1::/48
      100::/64
      2001::/23
      2001:db8::/32
      2002::/16
      3fff::/20
      5f00::/16
      fc00::/7
      fe80::/10
      ff00::/8
    ].freeze
    # Reading order for the v4 half: "this host on this network" (RFC 1122);
    # RFC 1918 private ×3; shared CGNAT (RFC 6598) — real users, but never a
    # provider's own globally-reachable space; loopback, which also neuters an
    # NXDOMAIN-hijacking resolver feeding the resolve_hostnames path;
    # link-local (RFC 3927); IETF protocol assignments (RFC 6890); TEST-NET-1/
    # 2/3 (RFC 5737) — three of the Vultr rows; the deprecated 6to4 relay
    # anycast (RFC 7526); benchmarking (RFC 2544); multicast, never a unicast
    # egress address; and reserved incl. 255.255.255.255 (RFC 1112). That is
    # 13.8% of IPv4, essentially all of it 224/4 + 240/4.
    # And the v6 half: unspecified; loopback; IPv4-mapped, which parses as
    # IPv6 in every client so a v4-mapped token would otherwise land in the v6
    # overlay; local-use translation (RFC 8215); discard-only (RFC 6666);
    # IETF protocol assignments incl. Teredo, BMWG 2001:2::/48 and deprecated
    # ORCHID 2001:10::/28 (two more Vultr rows); documentation (RFC 3849),
    # which is NOT inside 2001::/23; 6to4 (RFC 3056); documentation
    # (RFC 9637); SRv6 SIDs (RFC 9602); ULA, link-local, multicast.

    # A hostile or broken source could publish tens of thousands of bogons;
    # one WARN each would be its own denial of service on the log pipeline.
    MAX_BOGON_WARNINGS = 20

    BOGON_RANGES = begin
      buckets = { ipv4: [], ipv6: [] }
      BOGON_CIDRS.each do |cidr|
        family, first, last = CidrUtils.parse(cidr)
        raise "unparseable bogon prefix #{cidr.inspect}" unless family

        buckets[family] << [first, last]
      end
      buckets.transform_values { |rs| CidrUtils.merge(rs) }.freeze
    end

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
      # Never let a third party's file put IANA special-purpose space into a
      # client overlay. A source that is ENTIRELY bogon now yields 0 ranges
      # and falls into the keep-stale branch below, which is correct.
      ranges = strip_bogons(ranges, id)
      total = ranges[:ipv4].length + ranges[:ipv6].length
      if total.zero?
        # An empty security list is far more likely upstream breakage than
        # reality — keep whatever we had (keep_stale), record loudly.
        @store.record_failure(id, "parsed 0 ranges — upstream format changed? keeping stale data")
        return false
      end

      @store.write(id, maps_to: source["maps_to"], provider: source["provider"],
                       role: source["role"], etag: new_etag, ranges_by_family: ranges)
      @logger.info("openasn: tier B #{id}: #{ranges[:ipv4].length} v4 + #{ranges[:ipv6].length} v6 ranges")
      true
    rescue StandardError => e
      # keep_stale: failure is recorded, previous overlay files stay live.
      @store.record_failure(id, "#{e.class}: #{e.message}")
      @logger.warn("openasn: tier B #{id} failed (#{e.message}); keeping stale data")
      false
    end

    # Clip IANA special-purpose space out of one source's parsed ranges.
    #
    # In and out are both { ipv4: [[s, e], …], ipv6: […] } sorted and merged;
    # clipping can only shrink or split a range, never re-order or re-adjoin
    # one, so the result stays in that form and needs no re-merge.
    #
    # Each clipped range is reported once at WARN with the source id — a
    # provider publishing test networks as its own space is a fact about that
    # provider its users deserve to see, not something to swallow.
    def strip_bogons(ranges_by_family, id)
      out = {}
      %i[ipv4 ipv6].each do |family|
        kept = []
        clipped = []
        (ranges_by_family[family] || []).each do |(first, last)|
          pieces = CidrUtils.subtract(first, last, BOGON_RANGES[family])
          clipped << [first, last] unless pieces == [[first, last]]
          kept.concat(pieces)
        end
        out[family] = kept

        clipped.first(MAX_BOGON_WARNINGS).each do |(first, last)|
          @logger.warn("openasn: tier B #{id} publishes IANA special-purpose space " \
                       "#{format_range(family, first, last)} — clipped out of the overlay " \
                       "(a Tier B source is a remote party this project does not control)")
        end
        if clipped.length > MAX_BOGON_WARNINGS
          @logger.warn("openasn: tier B #{id}: #{clipped.length - MAX_BOGON_WARNINGS} further " \
                       "#{family} special-purpose ranges clipped (not listed)")
        end
      end
      out
    end

    def format_range(family, first, last)
      af = family == :ipv4 ? Socket::AF_INET : Socket::AF_INET6
      "#{IPAddr.new(first, af)}-#{IPAddr.new(last, af)}"
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
