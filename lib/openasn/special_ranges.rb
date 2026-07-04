# frozen_string_literal: true

require "ipaddr"

module OpenASN
  # Hardcoded special-purpose ranges, checked before any data layer.
  # These are IANA facts, not data: they never change with dataset updates.
  module SpecialRanges
    def self.table(cidrs)
      cidrs.map do |(cidr, verdict, rule)|
        r = IPAddr.new(cidr).to_range
        [r.first.to_i, r.last.to_i, verdict, rule].freeze
      end.freeze
    end

    V4 = table([
      ["0.0.0.0/8",      :private, :special_reserved],
      ["10.0.0.0/8",     :private, :special_rfc1918],
      ["100.64.0.0/10",  :cgnat,   :special_cgnat],      # RFC 6598 shared address space
      ["127.0.0.0/8",    :private, :special_loopback],
      ["169.254.0.0/16", :private, :special_link_local],
      ["172.16.0.0/12",  :private, :special_rfc1918],
      ["192.168.0.0/16", :private, :special_rfc1918],
      ["224.0.0.0/4",    :private, :special_multicast],
      ["240.0.0.0/4",    :private, :special_reserved]
    ]).freeze

    V6 = table([
      ["::1/128",   :private, :special_loopback],
      ["fc00::/7",  :private, :special_ula],
      ["fe80::/10", :private, :special_link_local]
    ]).freeze

    # -> [verdict, rule] | nil. Linear scan is optimal here: 9 rows max,
    # sorted so RFC1918/loopback hits early; measured faster than any
    # cleverer structure at this size.
    def self.match(ip_int, family)
      (family == :ipv4 ? V4 : V6).each do |(s, e, verdict, rule)|
        return [verdict, rule] if ip_int >= s && ip_int <= e
      end
      nil
    end
  end
end
