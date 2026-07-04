# frozen_string_literal: true

require "json"
require "fileutils"

module OpenASN
  # On-disk store for Tier B overlays under {data_dir}/overlays/.
  #
  # Files: {source_id}-ipv4.bin / {source_id}-ipv6.bin — raw concatenated
  # big-endian (start, end) pairs, sorted and merged. No header: these are
  # internal files owned by this gem, versioned by the `schema` field in
  # state.json, and always written atomically (tmp + rename) so a reader
  # process can never observe a torn file.
  #
  # state.json tracks per-source metadata: what it maps to, when it was
  # fetched, ETag for conditional GETs, and the last error (keep-stale
  # semantics: a failing source keeps serving its previous data, loudly).
  class OverlayStore
    SCHEMA = 1

    Entry = Struct.new(:id, :maps_to, :provider, :v4, :v6, keyword_init: true)

    def initialize(data_dir)
      @dir = File.join(data_dir, "overlays")
      @state_path = File.join(@dir, "state.json")
    end

    def state
      return { "schema" => SCHEMA, "sources" => {} } unless File.exist?(@state_path)

      parsed = JSON.parse(File.read(@state_path))
      # Unknown future schema: treat as empty rather than misread it.
      parsed["schema"] == SCHEMA ? parsed : { "schema" => SCHEMA, "sources" => {} }
    rescue JSON::ParserError
      { "schema" => SCHEMA, "sources" => {} }
    end

    def source_state(id) = state.dig("sources", id) || {}

    # ranges_by_family: { ipv4: [[s,e],...] (sorted, merged), ipv6: [...] }
    def write(id, maps_to:, provider: nil, etag: nil, ranges_by_family:)
      FileUtils.mkdir_p(@dir)
      counts = {}
      %i[ipv4 ipv6].each do |family|
        ranges = ranges_by_family[family] || []
        counts[family] = ranges.length
        packed = ranges.map { |(s, e)| BinaryFormat.pack_addr(s, family) + BinaryFormat.pack_addr(e, family) }.join
        path = file_path(id, family)
        File.binwrite("#{path}.tmp", packed)
        File.rename("#{path}.tmp", path)
      end
      update_state(id) do |entry|
        entry.merge(
          "maps_to" => maps_to.to_s, "provider" => provider, "etag" => etag,
          "fetched_at" => Time.now.utc.iso8601,
          "records_ipv4" => counts[:ipv4], "records_ipv6" => counts[:ipv6],
          "last_error" => nil
        )
      end
    end

    def record_failure(id, error_message)
      update_state(id) do |entry|
        entry.merge("last_error" => error_message, "last_attempt_at" => Time.now.utc.iso8601)
      end
    end

    def record_fresh(id)
      update_state(id) do |entry|
        entry.merge("fetched_at" => Time.now.utc.iso8601, "last_error" => nil)
      end
    end

    def fetched_at(id)
      ts = source_state(id)["fetched_at"]
      ts && Time.parse(ts)
    rescue ArgumentError
      nil
    end

    # Load every stored overlay among enabled_ids into memory.
    def load(enabled_ids, mode)
      sources = state["sources"]
      enabled_ids.filter_map do |id|
        meta = sources[id]
        next unless meta

        v4 = load_family(id, :ipv4, mode)
        v6 = load_family(id, :ipv6, mode)
        next unless v4 || v6

        Entry.new(id: id, maps_to: meta["maps_to"], provider: meta["provider"],
                  v4: v4, v6: v6)
      end
    end

    def clear!(id)
      %i[ipv4 ipv6].each { |f| FileUtils.rm_f(file_path(id, f)) }
    end

    private

    def file_path(id, family) = File.join(@dir, "#{id}-#{family}.bin")

    def load_family(id, family, mode)
      path = file_path(id, family)
      return nil unless File.exist?(path)

      bytes = File.binread(path)
      # A torn/odd-sized file would corrupt binary search: drop the tail.
      rec = BinaryFormat.overlay_rec_size(family)
      bytes = bytes[0, bytes.bytesize - (bytes.bytesize % rec)] if (bytes.bytesize % rec).positive?
      BinaryFormat::OverlayLayer.build(bytes, family, mode)
    end

    def update_state(id)
      FileUtils.mkdir_p(@dir)
      current = state
      current["sources"][id] = yield(current["sources"][id] || {})
      File.write("#{@state_path}.tmp", JSON.pretty_generate(current))
      File.rename("#{@state_path}.tmp", @state_path)
    end
  end
end
