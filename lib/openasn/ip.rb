# frozen_string_literal: true

require "ipaddr"

module OpenASN
  # IP input parsing. Hot path: dotted-quad IPv4 strings (the overwhelming
  # majority of real lookups) are parsed by hand — ~6x faster than
  # IPAddr.new, which matters when the whole lookup budget is ~20µs.
  # Everything else (IPv6, IPAddr instances, mapped addresses) goes through
  # IPAddr for correctness.
  module IP
    module_function

    # -> [family(:ipv4 | :ipv6), Integer]
    # Raises OpenASN::InvalidIPError (an ArgumentError) on anything else.
    def parse(input)
      case input
      when IPAddr
        from_ipaddr(input)
      when String
        fast_v4(input) || from_string(input)
      else
        raise InvalidIPError, "expected an IP address String or IPAddr, got #{input.class}"
      end
    end

    def fast_v4(str)
      parts = str.split(".")
      return nil unless parts.length == 4

      int = 0
      parts.each do |p|
        # Reject empty octets, leading zeros ("01" is ambiguous octal in
        # many parsers — safer to fall through to IPAddr, which rejects it),
        # non-digits, and >255.
        return nil if p.empty? || p.length > 3 || (p.length > 1 && p.start_with?("0"))

        n = 0
        p.each_char do |c|
          d = c.ord - 48
          return nil if d.negative? || d > 9

          n = n * 10 + d
        end
        return nil if n > 255

        int = (int << 8) | n
      end
      [:ipv4, int]
    end

    def from_string(str)
      from_ipaddr(IPAddr.new(str))
    rescue IPAddr::Error
      raise InvalidIPError, "invalid IP address: #{str.inspect}"
    end

    def from_ipaddr(ip)
      if ip.ipv4?
        [:ipv4, ip.to_i]
      elsif ip.ipv4_mapped?
        # ::ffff:1.2.3.4 arrives on dual-stack sockets constantly; classify
        # as the embedded IPv4 — that's the address doing the talking.
        [:ipv4, ip.native.to_i]
      else
        [:ipv6, ip.to_i]
      end
    end
  end
end
