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
