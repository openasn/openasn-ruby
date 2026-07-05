# frozen_string_literal: true

require "json"
require "rexml/document"
require "zlib"

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

    # --- structured VPN provider publications -------------------------------

    register "mullvad_relays_json" do |body|
      data = JSON.parse(body)
      raise ParseError, "mullvad_relays_json: expected array" unless data.is_a?(Array)

      # First-party public API behind https://mullvad.net/en/servers. Mozilla
      # VPN / Firefox VPN use Mullvad infrastructure, but the relay list cannot
      # distinguish a Mozilla customer from a direct Mullvad customer, so the
      # provider attribution remains the network operator: Mullvad.
      tokens = data.select { |r| r["active"] != false }.flat_map do |relay|
        [relay["ipv4_addr_in"], relay["ipv6_addr_in"]]
      end.compact
      raise ParseError, "mullvad_relays_json: no active relay IPs — schema changed?" if tokens.empty?

      tokens.uniq
    end

    register "ivpn_servers_json" do |body|
      data = JSON.parse(body)
      tokens = []
      (data["wireguard"] || []).each do |location|
        (location["hosts"] || []).each { |host| tokens << host["host"] }
      end
      (data["openvpn"] || []).each do |location|
        tokens.concat(location["ip_addresses"] || [])
      end
      tokens.compact!
      raise ParseError, "ivpn_servers_json: no server IPs — schema changed?" if tokens.empty?

      tokens.uniq
    end

    register "pia_servers_json" do |body|
      # PIA appends a detached signature after the first JSON line. The first
      # line is the server document the official clients consume.
      data = JSON.parse(body.lines.first.to_s)
      tokens = (data["regions"] || []).flat_map do |region|
        next [] if region["offline"] == true

        (region["servers"] || {}).values.flatten.filter_map { |server| server["ip"] }
      end
      raise ParseError, "pia_servers_json: no server IPs — schema changed?" if tokens.empty?

      tokens.uniq
    end

    register "airvpn_status_json" do |body|
      data = JSON.parse(body)
      tokens = (data["servers"] || []).flat_map do |server|
        server.filter_map do |key, value|
          value if key.match?(/\Aip_v[46]_in\d+\z/)
        end
      end
      raise ParseError, "airvpn_status_json: no entry IPs — schema changed?" if tokens.empty?

      tokens.uniq
    end

    register "windscribe_serverlist_json" do |body|
      data = JSON.parse(body)
      tokens = (data["data"] || []).flat_map do |location|
        next [] unless location["status"] == 1

        (location["groups"] || []).flat_map do |group|
          group_tokens = [group["ping_ip"]]
          group_tokens.concat((group["nodes"] || []).flat_map { |node| [node["ip"], node["ip2"], node["ip3"]] })
          group_tokens
        end
      end.compact
      raise ParseError, "windscribe_serverlist_json: no server IPs — schema changed?" if tokens.empty?

      tokens.uniq
    end

    register "privado_servers_json" do |body|
      data = JSON.parse(body)
      tokens = (data["servers"] || []).filter_map { |server| server["ip"] }
      raise ParseError, "privado_servers_json: no server IPs — schema changed?" if tokens.empty?

      tokens.uniq
    end

    register "leap_eip_service_json" do |body|
      data = JSON.parse(body)
      tokens = (data["gateways"] || []).filter_map { |gateway| gateway["ip_address"] }
      raise ParseError, "leap_eip_service_json: no gateway IPs — schema changed?" if tokens.empty?

      tokens.uniq
    end

    register "wlvpn_server_list_xml" do |body|
      doc = REXML::Document.new(body)
      tokens = []
      doc.elements.each("//server") do |server|
        next unless server.attributes["visible"].to_s == "1" && server.attributes["status"].to_s == "1"

        ip = server.attributes["ip"].to_s.strip
        tokens << ip unless ip.empty?
      end
      raise ParseError, "wlvpn_server_list_xml: no visible active server IPs — schema changed?" if tokens.empty?

      tokens.uniq
    end

    register "surfshark_clusters_json" do |body|
      data = JSON.parse(body)
      raise ParseError, "surfshark_clusters_json: expected array" unless data.is_a?(Array)

      tokens = data.filter_map { |cluster| cluster["connectionName"] }
      raise ParseError, "surfshark_clusters_json: no connectionName hostnames — schema changed?" if tokens.empty?

      tokens.uniq
    end

    register "nordvpn_servers_json" do |body|
      data = JSON.parse(body)
      data = data["servers"] if data.is_a?(Hash)
      raise ParseError, "nordvpn_servers_json: expected array" unless data.is_a?(Array)

      tokens = data.select { |server| server["status"] == "online" }.flat_map do |server|
        ips = [server["station"], server["ipv6_station"], server["station_ipv6"]]
        ips.concat((server["ips"] || []).filter_map { |entry| entry.dig("ip", "ip") })
        ips
      end.compact.reject(&:empty?)
      raise ParseError, "nordvpn_servers_json: no server IPs — schema changed?" if tokens.empty?

      tokens.uniq
    end

    register "vpngate_csv" do |body|
      tokens = body.each_line.filter_map do |line|
        next if line.start_with?("*", "#")

        line.split(",", 3)[1]&.strip
      end
      raise ParseError, "vpngate_csv: no relay IPs — schema changed?" if tokens.empty?

      tokens.uniq
    end

    register "ovpn_zip_remote_hosts" do |body|
      tokens = unzip_files(body).flat_map do |name, content|
        # TunnelBear's first-party Linux ZIP currently includes a few valid
        # OpenVPN configs with a defensive ".ovpn.txt" suffix. Accept only
        # the two explicit OpenVPN suffixes so README/license text cannot
        # accidentally become source data.
        next [] unless name.downcase.end_with?(".ovpn", ".ovpn.txt")

        openvpn_remote_hosts(content)
      end
      raise ParseError, "ovpn_zip_remote_hosts: no OpenVPN remote hosts — schema changed?" if tokens.empty?

      tokens.uniq
    end

    register "vpnbook_html_hosts" do |body|
      tokens = body.scan(/\b[a-z0-9-]+\.vpnbook\.com\b/i).reject { |host| host.downcase == "www.vpnbook.com" }
      raise ParseError, "vpnbook_html_hosts: no vpnbook.com hosts — schema changed?" if tokens.empty?

      tokens.uniq
    end

    register "html_table_hostnames" do |body|
      tokens = body.scan(%r{<td>\s*([a-z0-9.-]+\.[a-z]{2,63})\s*</td>}i).flatten
      raise ParseError, "html_table_hostnames: no hostnames — schema changed?" if tokens.empty?

      tokens.uniq
    end

    register "strongvpn_locations_html" do |body|
      tokens = body.scan(/\bvpn-[a-z0-9-]+\.reliablehosting\.com\b/i).map(&:downcase)
      raise ParseError, "strongvpn_locations_html: no StrongVPN hostnames — schema changed?" if tokens.empty?

      tokens.uniq
    end

    register "vpnsecure_locations_html" do |body|
      tokens = body.scan(%r{</div>\s*([a-z]{2,3}\d+)\s*<span[^>]*class=["'][^"']*\bstatus--up\b[^"']*["'][^>]*>\s*up\s*</span>}i)
                   .flatten
                   .map { |host| "#{host.downcase}.isponeder.com" }
      raise ParseError, "vpnsecure_locations_html: no up hosts — schema changed?" if tokens.empty?

      tokens.uniq
    end

    class << self
      private

      def openvpn_remote_hosts(content)
        content.each_line.filter_map do |line|
          match = line.match(/\Aremote\s+([^\s]+)(?:\s|$)/i)
          match && match[1].delete_prefix("[").delete_suffix("]")
        end
      end

      # Deflate expands up to ~1000:1 and these archives arrive from remote
      # servers: cap inflated output so a hostile/compromised archive costs
      # at most bounded memory (ParseError -> keep-stale), never an OOM.
      # Real provider config archives inflate to single-digit MB.
      MAX_INFLATED_BYTES = 64 * 1024 * 1024

      # Minimal ZIP reader for first-party OpenVPN config archives. We keep
      # this in stdlib Ruby instead of adding rubyzip so the gem stays
      # dependency-free. It supports the two methods seen in provider archives:
      # stored (0) and deflated (8), using the central directory so data
      # descriptors in local file headers do not matter.
      def unzip_files(body)
        bytes = body.b
        eocd = bytes.rindex("PK\x05\x06".b) or raise ParseError, "zip: missing end of central directory"
        entries = bytes.byteslice(eocd + 10, 2).unpack1("v")
        cd_offset = bytes.byteslice(eocd + 16, 4).unpack1("V")
        pos = cd_offset
        files = []
        total_inflated = 0

        entries.times do
          raise ParseError, "zip: malformed central directory" unless bytes.byteslice(pos, 4) == "PK\x01\x02".b

          method = bytes.byteslice(pos + 10, 2).unpack1("v")
          compressed_size = bytes.byteslice(pos + 20, 4).unpack1("V")
          name_length = bytes.byteslice(pos + 28, 2).unpack1("v")
          extra_length = bytes.byteslice(pos + 30, 2).unpack1("v")
          comment_length = bytes.byteslice(pos + 32, 2).unpack1("v")
          local_offset = bytes.byteslice(pos + 42, 4).unpack1("V")
          name = bytes.byteslice(pos + 46, name_length).force_encoding(Encoding::UTF_8).scrub
          pos += 46 + name_length + extra_length + comment_length

          next if name.end_with?("/")
          raise ParseError, "zip: malformed local header for #{name}" unless bytes.byteslice(local_offset, 4) == "PK\x03\x04".b

          local_name_length = bytes.byteslice(local_offset + 26, 2).unpack1("v")
          local_extra_length = bytes.byteslice(local_offset + 28, 2).unpack1("v")
          data_start = local_offset + 30 + local_name_length + local_extra_length
          compressed = bytes.byteslice(data_start, compressed_size)
          content = case method
                    when 0 then compressed
                    when 8 then bounded_inflate(compressed, name)
                    else
                      raise ParseError, "zip: unsupported compression method #{method} for #{name}"
                    end
          total_inflated += content.bytesize
          raise ParseError, "zip: archive inflates past #{MAX_INFLATED_BYTES} bytes - refusing" if total_inflated > MAX_INFLATED_BYTES

          files << [name, content.force_encoding(Encoding::UTF_8).scrub]
        end

        files
      end

      # Inflate in chunks, aborting the moment cumulative output crosses the
      # cap; the bomb never gets to materialize in memory.
      def bounded_inflate(compressed, name)
        inflater = Zlib::Inflate.new(-Zlib::MAX_WBITS)
        out = +"".b
        begin
          inflater.inflate(compressed) do |chunk|
            out << chunk
            raise ParseError, "zip: #{name} inflates past #{MAX_INFLATED_BYTES} bytes - refusing" if out.bytesize > MAX_INFLATED_BYTES
          end
          out << inflater.finish unless inflater.finished?
        ensure
          inflater.close
        end
        out
      end
    end
  end
end
