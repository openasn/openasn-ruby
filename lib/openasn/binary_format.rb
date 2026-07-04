# frozen_string_literal: true

module OpenASN
  # Reader for the OASN v1 artifact format and the OORG v1 org-names
  # sidecar. The byte-exact spec lives in the data repo:
  # https://github.com/openasn/openasn/blob/main/FORMAT.md — this file is an
  # independent implementation of that document and must never drift from
  # it. All integers big-endian. Readers REJECT unknown format versions on
  # purpose: half-understanding an artifact is worse than keeping last-good
  # data.
  module BinaryFormat
    MAGIC = "OASN"
    ORG_MAGIC = "OORG"
    FORMAT_VERSION = 0x01
    HEADER_SIZE = 32
    ORG_HEADER_SIZE = 16

    # flags (u16) bit layout — see FORMAT.md
    FLAG_BAD_ASN       = 1 << 8
    FLAG_VPN_PROVIDER  = 1 << 9
    FLAG_MOBILE        = 1 << 10
    FLAG_ENTERPRISE_GW = 1 << 11
    FLAG_CDN           = 1 << 12
    FLAG_HOSTING_EXTRA = 1 << 13

    CATEGORY_MASK = 0x000F
    ROLE_SHIFT    = 4
    ROLE_MASK     = 0x00F0

    CATEGORIES = [nil, "isp", "hosting", "business", "education_research", "government_admin"].freeze
    ROLES      = [nil, "tier1_transit", "major_transit", "midsize_transit",
                  "access_provider", "content_network", "stub"].freeze

    FLAG_NAMES = {
      FLAG_BAD_ASN => :bad_asn,
      FLAG_VPN_PROVIDER => :vpn_provider,
      FLAG_MOBILE => :mobile_carrier,
      FLAG_ENTERPRISE_GW => :enterprise_gw,
      FLAG_CDN => :cdn,
      FLAG_HOSTING_EXTRA => :hosting_extra
    }.freeze

    module_function

    def category_name(flags) = CATEGORIES[flags & CATEGORY_MASK]
    def role_name(flags)     = ROLES[(flags & ROLE_MASK) >> ROLE_SHIFT]

    def flag_names(flags)
      FLAG_NAMES.filter_map { |bit, name| name if flags.anybits?(bit) }
    end

    def addr_size(family)        = family == :ipv4 ? 4 : 16
    def base_rec_size(family)    = family == :ipv4 ? 14 : 38
    def overlay_rec_size(family) = family == :ipv4 ? 8 : 32

    def pack_addr(int, family)
      if family == :ipv4
        [int].pack("N")
      else
        [int >> 64, int & 0xFFFF_FFFF_FFFF_FFFF].pack("Q>Q>")
      end
    end

    # Parse a full OASN artifact into its layers.
    # -> { family:, build_ts:, base: BaseLayer, vpn: OverlayLayer, dc: OverlayLayer, relay: OverlayLayer }
    def parse_artifact(bytes, mode: :packed)
      raise FormatError, "not an OASN artifact (bad magic)" unless bytes[0, 4] == MAGIC

      version = bytes.getbyte(4)
      raise FormatError, "unsupported OASN format_version #{version} (this gem speaks v#{FORMAT_VERSION}); update the openasn gem" unless version == FORMAT_VERSION

      family = bytes.getbyte(5) == 0x04 ? :ipv4 : :ipv6
      build_ts = bytes[8, 8].unpack1("Q>")
      base_n, vpn_n, dc_n, relay_n = bytes[16, 16].unpack("NNNN")

      brec = base_rec_size(family)
      orec = overlay_rec_size(family)
      expected = HEADER_SIZE + base_n * brec + (vpn_n + dc_n + relay_n) * orec
      raise FormatError, "artifact truncated or padded: #{bytes.bytesize} bytes, header implies #{expected}" unless bytes.bytesize == expected

      offset = HEADER_SIZE
      base  = bytes[offset, base_n * brec];  offset += base_n * brec
      vpn   = bytes[offset, vpn_n * orec];   offset += vpn_n * orec
      dc    = bytes[offset, dc_n * orec];    offset += dc_n * orec
      relay = bytes[offset, relay_n * orec]

      {
        family: family, build_ts: build_ts,
        base: BaseLayer.build(base, family, mode),
        vpn: OverlayLayer.build(vpn, family, mode),
        dc: OverlayLayer.build(dc, family, mode),
        relay: OverlayLayer.build(relay, family, mode)
      }
    end

    # --- Base layer: [start, end, asn, flags] records -----------------------

    module BaseLayer
      def self.build(bytes, family, mode)
        mode == :arrays ? ArraysBase.new(bytes, family) : PackedBase.new(bytes, family)
      end
    end

    # Packed mode: binary search directly over the artifact bytes.
    # ~6MB resident for all of IPv4, ~19µs/lookup (measured on the format's
    # validation prototype). Key comparisons happen on raw big-endian
    # address bytes: for unsigned BE values, bytewise String comparison IS
    # numeric comparison, which lets IPv4 and IPv6 share one search.
    class PackedBase
      attr_reader :count

      def initialize(bytes, family)
        @bytes = bytes.freeze
        @family = family
        @asz = BinaryFormat.addr_size(family)
        @rec = BinaryFormat.base_rec_size(family)
        @count = bytes.bytesize / @rec
      end

      # -> [asn, flags] | nil
      def find(ip_int)
        key = BinaryFormat.pack_addr(ip_int, @family)
        lo = 0
        hi = @count - 1
        while lo <= hi
          mid = (lo + hi) / 2
          off = mid * @rec
          if key < @bytes[off, @asz]
            hi = mid - 1
          elsif key > @bytes[off + @asz, @asz]
            lo = mid + 1
          else
            return @bytes[off + 2 * @asz, 6].unpack("Nn")
          end
        end
        nil
      end
    end

    # Arrays mode: unpack once into parallel Integer arrays. Measured on
    # the real dataset: full lookups drop from ~15µs to ~9µs (the raw
    # range probe alone is ~2µs, but IP parsing + overlay checks dominate
    # the classify pipeline) at several× the memory. Worth it for
    # lookup-heavy batch paths; configure via `memory_mode :arrays`.
    class ArraysBase
      attr_reader :count

      def initialize(bytes, family)
        asz = BinaryFormat.addr_size(family)
        rec = BinaryFormat.base_rec_size(family)
        @count = bytes.bytesize / rec
        @starts = Array.new(@count)
        @ends   = Array.new(@count)
        @asns   = Array.new(@count)
        @flags  = Array.new(@count)
        unpack_addr = family == :ipv4 ? ->(s) { s.unpack1("N") } : ->(s) { hi, lo = s.unpack("Q>Q>"); (hi << 64) | lo }
        @count.times do |i|
          off = i * rec
          @starts[i] = unpack_addr.call(bytes[off, asz])
          @ends[i]   = unpack_addr.call(bytes[off + asz, asz])
          @asns[i], @flags[i] = bytes[off + 2 * asz, 6].unpack("Nn")
        end
        [@starts, @ends, @asns, @flags].each(&:freeze)
      end

      def find(ip_int)
        i = bsearch_le(@starts, ip_int)
        return nil unless i && ip_int <= @ends[i]

        [@asns[i], @flags[i]]
      end

      private

      # Index of the greatest start <= ip_int (rightmost candidate range).
      def bsearch_le(arr, val)
        lo = 0
        hi = arr.length - 1
        ans = nil
        while lo <= hi
          mid = (lo + hi) / 2
          if arr[mid] <= val
            ans = mid
            lo = mid + 1
          else
            hi = mid - 1
          end
        end
        ans
      end
    end

    # --- Overlay layers: sorted disjoint [start, end] ranges ----------------

    module OverlayLayer
      def self.build(bytes, family, mode)
        mode == :arrays ? ArraysOverlay.new(bytes, family) : PackedOverlay.new(bytes, family)
      end
    end

    class PackedOverlay
      attr_reader :count

      def initialize(bytes, family)
        @bytes = bytes.freeze
        @family = family
        @asz = BinaryFormat.addr_size(family)
        @rec = BinaryFormat.overlay_rec_size(family)
        @count = bytes.bytesize / @rec
      end

      def cover?(ip_int)
        return false if @count.zero?

        key = BinaryFormat.pack_addr(ip_int, @family)
        lo = 0
        hi = @count - 1
        while lo <= hi
          mid = (lo + hi) / 2
          off = mid * @rec
          if key < @bytes[off, @asz]
            hi = mid - 1
          elsif key > @bytes[off + @asz, @asz]
            lo = mid + 1
          else
            return true
          end
        end
        false
      end
    end

    class ArraysOverlay
      attr_reader :count

      def initialize(bytes, family)
        asz = BinaryFormat.addr_size(family)
        rec = BinaryFormat.overlay_rec_size(family)
        @count = bytes.bytesize / rec
        @starts = Array.new(@count)
        @ends   = Array.new(@count)
        unpack_addr = family == :ipv4 ? ->(s) { s.unpack1("N") } : ->(s) { hi, lo = s.unpack("Q>Q>"); (hi << 64) | lo }
        @count.times do |i|
          off = i * rec
          @starts[i] = unpack_addr.call(bytes[off, asz])
          @ends[i]   = unpack_addr.call(bytes[off + asz, asz])
        end
        [@starts, @ends].each(&:freeze)
      end

      def cover?(ip_int)
        lo = 0
        hi = @count - 1
        while lo <= hi
          mid = (lo + hi) / 2
          if ip_int < @starts[mid]
            hi = mid - 1
          elsif ip_int > @ends[mid]
            lo = mid + 1
          else
            return true
          end
        end
        false
      end
    end

    # --- OORG v1: ASN -> organization name ----------------------------------

    class OrgIndex
      def self.load(path)
        new(File.binread(path))
      end

      def initialize(bytes)
        raise FormatError, "not an OORG file (bad magic)" unless bytes[0, 4] == ORG_MAGIC
        raise FormatError, "unsupported OORG version #{bytes.getbyte(4)}" unless bytes.getbyte(4) == 0x01

        @bytes = bytes.freeze
        @count, @blob_size = bytes[8, 8].unpack("NN")
        @blob_base = ORG_HEADER_SIZE + @count * 8
        expected = @blob_base + @blob_size
        raise FormatError, "OORG truncated: #{bytes.bytesize} bytes, header implies #{expected}" unless bytes.bytesize == expected
      end

      def name(asn)
        lo = 0
        hi = @count - 1
        while lo <= hi
          mid = (lo + hi) / 2
          a, off = @bytes[ORG_HEADER_SIZE + mid * 8, 8].unpack("NN")
          if asn < a
            hi = mid - 1
          elsif asn > a
            lo = mid + 1
          else
            nxt = mid + 1 < @count ? @bytes[ORG_HEADER_SIZE + (mid + 1) * 8 + 4, 4].unpack1("N") : @blob_size
            return @bytes[@blob_base + off, nxt - off].force_encoding(Encoding::UTF_8)
          end
        end
        nil
      end
    end
  end
end
