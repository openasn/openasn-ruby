# frozen_string_literal: true

require "ipaddr"

module OpenASN
  # Range math for the Tier B executor. Mirrors the data pipeline's
  # semantics exactly (adjacent ranges merge; inputs may overlap freely).
  module CidrUtils
    module_function

    # "1.2.3.0/24" | "1.2.3.4" -> [family, start_int, end_int] | nil (junk)
    def parse(token)
      ip = IPAddr.new(token.strip)
      r = ip.to_range
      [ip.ipv4? ? :ipv4 : :ipv6, r.first.to_i, r.last.to_i]
    rescue IPAddr::Error
      nil
    end

    # Merge overlapping AND adjacent ranges. Critical for Apple's relay
    # list: ~280k rows collapse dramatically once merged, which is the
    # difference between a fat linear file and a lookup-friendly overlay.
    def merge(ranges)
      return [] if ranges.empty?

      sorted = ranges.sort_by { |r| [r[0], r[1]] }
      merged = [[sorted[0][0], sorted[0][1]]]
      sorted.each do |(s, e)|
        last = merged.last
        if s <= last[1] + 1
          last[1] = e if e > last[1]
        else
          merged << [s, e]
        end
      end
      merged
    end

    # [start, finish] minus a SORTED, MERGED list of blocked ranges, as the
    # surviving pieces in ascending order (possibly none).
    #
    # CLIP, NOT DROP. A range that merely overlaps a blocked range keeps its
    # legitimate remainder: 192.0.0.0/22 minus the bogon table keeps
    # 192.0.1.0/24 and 192.0.3.0/24 and loses only the protocol-assignment
    # and TEST-NET-1 /24s. A filter that deleted a whole announcement because
    # it touched one blocked prefix would be worse than the bug it fixes.
    #
    # `blocked` MUST be sorted and merged (BOGON_RANGES is built that way) —
    # the early `break` relies on it.
    #
    # The Python client keeps the identical algorithm in tier_b.py's
    # `_subtract`; it lives here in Ruby because this is where range math
    # already lives.
    def subtract(start, finish, blocked)
      pieces = [[start, finish]]
      blocked.each do |(b_start, b_end)|
        break if b_start > finish # sorted: nothing further can overlap
        next if b_end < start

        remaining = []
        pieces.each do |(p_start, p_end)|
          if b_end < p_start || b_start > p_end
            remaining << [p_start, p_end]
            next
          end
          remaining << [p_start, b_start - 1] if p_start < b_start
          remaining << [b_end + 1, p_end] if p_end > b_end
        end
        pieces = remaining
        break if pieces.empty?
      end
      pieces
    end

    # tokens (CIDRs/IPs, junk tolerated) -> { ipv4: merged, ipv6: merged }
    def ranges_by_family(tokens)
      out = { ipv4: [], ipv6: [] }
      tokens.each do |token|
        family, s, e = parse(token)
        out[family] << [s, e] if family
      end
      { ipv4: merge(out[:ipv4]), ipv6: merge(out[:ipv6]) }
    end
  end
end
