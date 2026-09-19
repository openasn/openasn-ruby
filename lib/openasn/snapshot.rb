# frozen_string_literal: true

require "digest"
require "json"

module OpenASN
  # An immutable, fully-loaded dataset: canonical artifacts (both address
  # families) + org names + Tier B overlays, plus the metadata to explain
  # where it all came from. Snapshots are built off the hot path and
  # swapped in with a single ivar assignment (see Dataset) — readers never
  # see partial state, and there are no locks anywhere near lookups.
  class Snapshot
    SEED_DIR = File.expand_path("data/seed", __dir__)

    Family = Struct.new(:base, :vpn, :dc, :relay, keyword_init: true)

    attr_reader :v4, :v6, :orgs, :overlays, :build_id, :build_ts, :loaded_at,
                :origin, :tier_b_status, :record_counts

    # Build from the best available data:
    #   1. data_dir artifacts (downloaded by the updater) when present+valid
    #   2. the gem's bundled seed otherwise (first boot, corrupted dir, …)
    # A corrupt downloaded artifact NEVER crashes boot — parsing happens
    # INSIDE the fallback boundary (a truncated download that still reads
    # fine must not take the app down); we log and fall back to the seed,
    # and the next update cycle re-downloads. If the bundled seed itself
    # fails to parse, the gem is broken and raising IS correct.
    def self.build(config)
      data_dir = config.data_dir
      mode = config.memory_mode

      origin = :data_dir
      begin
        v4_bytes, v6_bytes, manifest = read_artifacts(data_dir)
        raise Errno::ENOENT, "no artifacts in data_dir" unless v4_bytes

        v4_parsed, v6_parsed = parse_pair(v4_bytes, v6_bytes, mode)
      rescue StandardError => e
        unless e.is_a?(Errno::ENOENT)
          config.logger.warn("openasn: data_dir artifacts unusable (#{e.message}); falling back to bundled seed")
        end
        origin = :seed
        v4_bytes = File.binread(File.join(SEED_DIR, "openasn-ipv4.bin"))
        v6_bytes = File.binread(File.join(SEED_DIR, "openasn-ipv6.bin"))
        manifest = JSON.parse(File.read(File.join(SEED_DIR, "manifest.json")))
        v4_parsed, v6_parsed = parse_pair(v4_bytes, v6_bytes, mode)
      end

      orgs = load_orgs(data_dir, config)
      store = OverlayStore.new(data_dir)
      overlays = store.load(config.enabled_tier_b_source_ids, mode)
      recipe_orgs = store.load_names(config.enabled_tier_b_source_ids)

      new(v4_parsed, v6_parsed, orgs, overlays, manifest, origin, store, recipe_orgs: recipe_orgs)
    end

    def self.parse_pair(v4_bytes, v6_bytes, mode)
      v4_parsed = BinaryFormat.parse_artifact(v4_bytes, mode: mode)
      v6_parsed = BinaryFormat.parse_artifact(v6_bytes, mode: mode)
      raise FormatError, "openasn-ipv4.bin is not an IPv4 artifact" unless v4_parsed[:family] == :ipv4
      raise FormatError, "openasn-ipv6.bin is not an IPv6 artifact" unless v6_parsed[:family] == :ipv6

      [v4_parsed, v6_parsed]
    end

    def self.read_artifacts(data_dir)
      v4 = File.join(data_dir, "openasn-ipv4.bin")
      v6 = File.join(data_dir, "openasn-ipv6.bin")
      mf = File.join(data_dir, "manifest.json")
      return nil unless File.exist?(v4) && File.exist?(v6)

      manifest = File.exist?(mf) ? JSON.parse(File.read(mf)) : {}
      verify_manifest_hashes!(manifest, "openasn-ipv4.bin" => v4, "openasn-ipv6.bin" => v6)
      [File.binread(v4), File.binread(v6), manifest]
    end

    def self.verify_manifest_hashes!(manifest, files)
      by_name = (manifest["files"] || []).to_h { |f| [f["name"], f] }
      return if by_name.empty? # legacy/manual installs without checksums still parse through FORMAT.md.

      files.each do |name, path|
        expected = by_name.dig(name, "sha256")
        raise IntegrityError, "manifest missing checksum for #{name}" if expected.to_s.empty?

        actual = Digest::SHA256.file(path).hexdigest
        next if actual == expected

        # Updater writes manifest.json last as the commit marker. If a
        # process dies during the final rename loop, a fresh boot can see
        # new artifact bytes next to the old manifest. Reject that mixed
        # set here and fall back to the bundled seed instead of serving a
        # cross-build IPv4/IPv6 pair.
        raise IntegrityError, "#{name} checksum does not match manifest"
      end
    end

    def self.load_orgs(data_dir, config)
      path = File.join(data_dir, "openasn-orgs.bin")
      return nil unless File.exist?(path)

      BinaryFormat::OrgIndex.load(path)
    rescue StandardError => e
      config.logger.warn("openasn: openasn-orgs.bin unusable (#{e.message}); as_org will be nil until next update")
      nil
    end

    def initialize(v4_parsed, v6_parsed, orgs, overlays, manifest, origin, store, recipe_orgs: nil)
      @v4 = Family.new(base: v4_parsed[:base], vpn: v4_parsed[:vpn], dc: v4_parsed[:dc], relay: v4_parsed[:relay])
      @v6 = Family.new(base: v6_parsed[:base], vpn: v6_parsed[:vpn], dc: v6_parsed[:dc], relay: v6_parsed[:relay])
      @orgs = orgs
      @recipe_orgs = recipe_orgs
      @overlays = overlays.freeze
      @build_id = manifest["build_id"]
      @build_ts = v4_parsed[:build_ts]
      @loaded_at = Time.now.utc
      @origin = origin
      @record_counts = {
        base_ipv4: @v4.base.count, vpn_ipv4: @v4.vpn.count, dc_ipv4: @v4.dc.count,
        base_ipv6: @v6.base.count
      }.freeze
      @tier_b_status = build_tier_b_status(store)
      # Precomputed (family, maps_to) -> [[entry, layer], ...] index. The old
      # per-lookup filter_map was fine at 8 overlays but allocation-heavy at
      # 18+ (measured: 42us/lookup vs 15us overlay-less with 11 overlays -
      # most of the gap was these throwaway arrays, not the binary searches).
      # The snapshot is immutable, so build the index exactly once.
      @overlay_index = {}
      # Parallel index keyed by the optional `role` descriptor ("verified_crawler")
      # so provider attribution for roles costs the same single hash fetch as a
      # maps_to lookup and never scans the overlay list.
      @role_index = {}
      @overlays.each do |o|
        { ipv4: o.v4, ipv6: o.v6 }.each do |fam, layer|
          next unless layer

          (@overlay_index[[fam, o.maps_to]] ||= []) << [o, layer].freeze
          (@role_index[[fam, o.role]] ||= []) << [o, layer].freeze if o.role
        end
      end
      @overlay_index.each_value(&:freeze)
      @overlay_index.freeze
      @role_index.each_value(&:freeze)
      @role_index.freeze
      # Every distinct "flag:<name>" overlay present, so the classifier can
      # surface context flags for sources added to fetch-manifest.json AFTER
      # this gem shipped instead of only the two it was compiled knowing about.
      @context_flag_maps_to = @overlays.map(&:maps_to).uniq.select { |m| m.to_s.start_with?("flag:") }.freeze
      freeze
    end

    def family(fam) = fam == :ipv4 ? @v4 : @v6

    EMPTY_OVERLAYS = [].freeze

    # Overlays for one family in a stable order (executor wrote them; order
    # among same-precedence overlays doesn't affect verdicts, only which
    # provider gets attribution on exotic multi-overlay hits).
    def overlays_for(fam, maps_to)
      @overlay_index.fetch([fam, maps_to], EMPTY_OVERLAYS)
    end

    # Overlays carrying an optional `role` descriptor (e.g. "verified_crawler").
    def overlays_for_role(fam, role)
      @role_index.fetch([fam, role], EMPTY_OVERLAYS)
    end

    # The "flag:<name>" maps_to values this snapshot actually holds.
    attr_reader :context_flag_maps_to

    # Canonical CC0 name first (openasn-orgs.bin), then an opted-in Tier B
    # name table (fetch-manifest maps_to "as_org", e.g. ipverse_org_names).
    # Since 2026-09 the canonical sidecar names only ASNs with a clean
    # source (data repo DECISIONS.md D-SRC-2), so without the recipe most
    # ASNs have no name and as_org is nil.
    def org_name(asn)
      return nil unless asn

      @orgs&.name(asn) || @recipe_orgs&.name(asn)
    end

    def age_seconds
      Time.now.to_i - @build_ts
    end

    private

    def build_tier_b_status(store)
      state = store.state["sources"]
      status = @overlays.to_h do |o|
        s = state[o.id] || {}
        [o.id.to_sym, {
          maps_to: o.maps_to, fetched_at: s["fetched_at"],
          records: { ipv4: s["records_ipv4"], ipv6: s["records_ipv6"] },
          last_error: s["last_error"]
        }]
      end
      # Name tables have no ranges, so they are not overlays; report them too.
      state.each do |id, s|
        next unless s["maps_to"] == "as_org" && !status.key?(id.to_sym)

        status[id.to_sym] = { maps_to: "as_org", fetched_at: s["fetched_at"],
                              records: { names: s["records_names"] }, last_error: s["last_error"] }
      end
      status.freeze
    end
  end
end
