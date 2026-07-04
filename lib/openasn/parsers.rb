# frozen_string_literal: true

require "json"

module OpenASN
  # Tier B body parsers, keyed by the `parser` ids in fetch-manifest.json.
  #
  # Contract: parse(parser_id, body) -> Array of CIDR/IP string tokens
  # (junk tokens are fine — CidrUtils drops them). UNKNOWN parser ids make
  # #known? false and the executor SKIPS that source with a warning: that's
  # the forward-compatibility deal that lets the data repo add sources
  # without breaking old gems.
  #
  # Parsers are deliberately tolerant of cosmetic drift (extra columns,
  # comments, header rows) and deliberately strict about shape drift (a
  # JSON schema change raises ParseError -> the executor keeps stale data
  # and records the error, visible in OpenASN.dataset_info).
  module Parsers
    class ParseError < Error; end

    PARSERS = {}

    def self.register(id, &block) = PARSERS[id] = block
    def self.known?(id)           = PARSERS.key?(id)

    def self.parse(id, body)
      handler = PARSERS[id] or raise ParseError, "unknown parser #{id}"
      handler.call(body)
    rescue ParseError
      raise
    rescue StandardError => e
      raise ParseError, "#{id}: #{e.class}: #{e.message}"
    end

    # --- plain text shapes ---------------------------------------------------

    register "plain_ip_per_line" do |body|
      body.each_line.filter_map do |line|
        t = line.strip
        t unless t.empty? || t.start_with?("#")
      end
    end

    register "plain_cidr_per_line" do |body|
      body.each_line.filter_map do |line|
        t = line.strip
        t unless t.empty? || t.start_with?("#")
      end
    end

    # First CSV column is a CIDR; used by Apple's relay list
    # ("2.16.9.0/24,US,US-CA,,") and similar exports. Non-CIDR first
    # columns (headers) simply fail CIDR parsing downstream and drop out.
    register "csv_cidr_first_column" do |body|
      body.each_line.filter_map do |line|
        t = line.strip
        next if t.empty? || t.start_with?("#")

        t.split(",", 2).first&.strip
      end
    end

    # RFC 8805 geofeeds: "prefix,country,region,city,zip" with '#' comments.
    register "geofeed_csv" do |body|
      body.each_line.filter_map do |line|
        t = line.strip
        next if t.empty? || t.start_with?("#")

        t.split(",", 2).first&.strip
      end
    end

    # --- structured cloud publications ---------------------------------------

    register "aws_json" do |body|
      data = JSON.parse(body)
      v4 = (data["prefixes"] || []).filter_map { |p| p["ip_prefix"] }
      v6 = (data["ipv6_prefixes"] || []).filter_map { |p| p["ipv6_prefix"] }
      raise ParseError, "aws_json: no prefixes — schema changed?" if v4.empty? && v6.empty?

      v4 + v6
    end

    register "gcp_json" do |body|
      data = JSON.parse(body)
      prefixes = (data["prefixes"] || []).filter_map { |p| p["ipv4Prefix"] || p["ipv6Prefix"] }
      raise ParseError, "gcp_json: no prefixes — schema changed?" if prefixes.empty?

      prefixes
    end

    register "azure_servicetags_json" do |body|
      data = JSON.parse(body)
      prefixes = (data["values"] || []).flat_map { |v| v.dig("properties", "addressPrefixes") || [] }
      raise ParseError, "azure_servicetags_json: no addressPrefixes — schema changed?" if prefixes.empty?

      prefixes
    end

    register "oci_json" do |body|
      data = JSON.parse(body)
      cidrs = (data["regions"] || []).flat_map { |r| (r["cidrs"] || []).filter_map { |c| c["cidr"] } }
      raise ParseError, "oci_json: no cidrs — schema changed?" if cidrs.empty?

      cidrs
    end

    # Zscaler CENR: nested {"zscaler.net": {"continent …": {"city …": [{"range": …}]}}}.
    # Shape verified live 2026-07-04; we walk generically so cosmetic
    # nesting changes don't break us.
    register "zscaler_json" do |body|
      ranges = []
      walk = lambda do |node|
        case node
        when Hash
          ranges << node["range"] if node["range"].is_a?(String)
          node.each_value { |v| walk.call(v) }
        when Array
          node.each { |v| walk.call(v) }
        end
      end
      walk.call(JSON.parse(body))
      raise ParseError, "zscaler_json: no ranges — schema changed?" if ranges.empty?

      ranges
    end
  end
end
