# frozen_string_literal: true

require "ipaddr"
require "json"
require "time"
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

    # RFC 8805 geofeed again, but refusing to WIDEN a row.
    #
    # Cisco's SSE feed publishes 142 single reserved egress addresses with a
    # bogus /32 mask: `2603:5004:e0:107::135b/32`. Handing that to IPAddr
    # silently masks it to `2603:5004::/32` — a 2^96 block — and would stamp
    # enterprise_gateway across all of it on the evidence of one host route.
    # (ARIN says 2603:5000::/24 is "Cisco Systems Cloud Division", so the
    # widened claim would not be *false*; it would just be an enormous claim
    # built from a pinhole. Prefer false negatives.)
    #
    # So: a row whose address has bits set below its stated prefix length is
    # emitted as a host route instead. Rows that are already exact networks
    # pass through untouched, which is every IPv4 row and 267 of 409 IPv6
    # rows in that feed as of 2026-09-12.
    register "geofeed_csv_no_widen" do |body|
      tokens = body.each_line.filter_map do |line|
        t = line.strip
        next if t.empty? || t.start_with?("#")

        token = t.split(",", 2).first.to_s.strip
        next if token.empty?

        address, length = token.split("/", 2)
        next token unless length

        begin
          exact = IPAddr.new(address)
          masked = IPAddr.new(token)
          exact == masked ? token : "#{address}/#{exact.ipv6? ? 128 : 32}"
        rescue StandardError
          token # junk falls through and CidrUtils drops it
        end
      end
      raise ParseError, "geofeed_csv_no_widen: no rows — feed empty or moved?" if tokens.empty?

      tokens
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

    # --- verified crawler / agent recognition lists ---------------------------

    # The de-facto standard shape for "these IPs are really our crawler",
    # first published by Google and since copied verbatim by Bing, OpenAI,
    # Perplexity, Common Crawl and others:
    #
    #   {"creationTime": "...", "prefixes": [{"ipv4Prefix": "..."},
    #                                        {"ipv6Prefix": "..."}]}
    #
    # One parser covers every publisher that follows it, so a new crawler
    # feed is a fetch-manifest entry with no gem release. Publishers that
    # deviate (Amazon's plain-text lists, Bing's variants) get their own id.
    register "crawler_ipranges_json" do |body|
      data = JSON.parse(body)
      raise ParseError, "crawler_ipranges_json: expected object" unless data.is_a?(Hash)

      prefixes = (data["prefixes"] || []).filter_map do |p|
        next unless p.is_a?(Hash)

        p["ipv4Prefix"] || p["ipv6Prefix"] || p["ipv4prefix"] || p["ipv6prefix"]
      end
      raise ParseError, "crawler_ipranges_json: no prefixes — schema changed?" if prefixes.empty?

      prefixes
    end

    # Amazon publishes its bot lists as a JSON document embedded in a
    # documentation PAGE (~490 KB of HTML wrapping ~25 KB of JSON) inside
    # `<pre><code class="container">…</code></pre>`, and the three files
    # disagree with each other: amazonbot / live-ip-addresses use
    # `ipv4Prefix` with BARE addresses ("52.4.5.6", no /32), while
    # searchbot-ip-addresses uses AWS's `ip_prefix` key with the /32 already
    # present. Normalise both, and append /32 only when the value has no
    # prefix length — appending blindly would corrupt a real CIDR the day
    # Amazon starts publishing one.
    register "amazon_bot_html_json" do |body|
      block = body[%r{<pre>\s*<code[^>]*class=["'][^"']*\bcontainer\b[^"']*["'][^>]*>(.*?)</code>\s*</pre>}m, 1]
      raise ParseError, "amazon_bot_html_json: no <pre><code class=container> block — page changed?" unless block

      json = block.gsub("&quot;", '"').gsub("&amp;", "&").gsub("&lt;", "<").gsub("&gt;", ">")
      prefixes = (JSON.parse(json)["prefixes"] || []).filter_map do |p|
        next unless p.is_a?(Hash)

        value = p["ipv4Prefix"] || p["ip_prefix"] || p["ipv6Prefix"] || p["ipv6_prefix"]
        next unless value.is_a?(String)

        value.include?("/") ? value : "#{value}/#{value.include?(':') ? 128 : 32}"
      end
      raise ParseError, "amazon_bot_html_json: no prefixes — schema changed?" if prefixes.empty?

      prefixes
    end

    # --- additional first-party cloud / platform publications ----------------

    # Fastly: {"addresses": ["23.235.32.0/20", …],
    #          "ipv6_addresses": ["2a04:4e40::/32", …]}
    register "fastly_public_ip_list_json" do |body|
      data = JSON.parse(body)
      prefixes = Array(data["addresses"]) + Array(data["ipv6_addresses"])
      raise ParseError, "fastly_public_ip_list_json: no addresses — schema changed?" if prefixes.empty?

      prefixes
    end

    # GitHub https://api.github.com/meta — a flat object whose values are
    # arrays of CIDRs grouped by service ("actions", "hooks", "api", "git",
    # "packages", "copilot", …) mixed with non-CIDR keys ("ssh_keys",
    # "verifiable_password_authentication", "domains"). Every CIDR in the
    # document is GitHub-operated datacenter space, so we take the union of
    # every top-level array entry that looks like a CIDR and stay immune to
    # GitHub adding service groups (which it does regularly).
    register "github_meta_json" do |body|
      data = JSON.parse(body)
      raise ParseError, "github_meta_json: expected object" unless data.is_a?(Hash)

      prefixes = data.each_value.flat_map do |value|
        next [] unless value.is_a?(Array)

        value.select { |v| v.is_a?(String) && v.include?("/") && v.match?(%r{\A[0-9a-fA-F:.]+/\d{1,3}\z}) }
      end.uniq
      raise ParseError, "github_meta_json: no CIDRs — schema changed?" if prefixes.empty?

      prefixes
    end

    # Atlassian https://ip-ranges.atlassian.com/ —
    # {"items": [{"cidr": "…", "product": ["jira"], "direction": ["egress"]}]}
    register "atlassian_ipranges_json" do |body|
      data = JSON.parse(body)
      items = data["items"]
      raise ParseError, "atlassian_ipranges_json: no items — schema changed?" unless items.is_a?(Array)

      cidrs = items.filter_map { |i| i["cidr"] if i.is_a?(Hash) }
      raise ParseError, "atlassian_ipranges_json: no cidrs — schema changed?" if cidrs.empty?

      cidrs
    end

    # A bare top-level JSON array of CIDR/IP strings — the shape several
    # smaller operators publish ("[\"1.2.3.0/24\", \"2.3.4.0/24\"]").
    register "json_string_array" do |body|
      data = JSON.parse(body)
      raise ParseError, "json_string_array: expected array" unless data.is_a?(Array)

      tokens = data.select { |v| v.is_a?(String) }.map(&:strip).reject(&:empty?)
      raise ParseError, "json_string_array: empty — schema changed?" if tokens.empty?

      tokens
    end

    # Cato Networks publishes its SASE PoP ranges in a knowledge-base
    # article — "We recommend that you add the IP ranges owned by Cato
    # Networks to the relevant ACL" — which is our exact use case. The page
    # is 1.6 MB of Document360 Angular SSR and the article body arrives
    # HTML-escaped inside an attribute, but digits, dots and slashes are not
    # escaped, so a CIDR scan over the raw response is both the simplest and
    # the most drift-tolerant reader. Measured 2026-09-12: exactly 43 CIDRs,
    # zero false positives from nav, footer, scripts or CSS.
    #
    # DO NOT try to parse the per-PoP "IP Range" tables instead. A single
    # cell concatenates multiple dash-delimited ranges with no separator
    # ("140.82.194.1 - 140.82.194.254113.30.130.1 - 113.30.130.254"), which
    # yields corrupt octets like "06.39.250.192". Requiring a prefix length
    # is what keeps those out, so the /NN is load-bearing, not incidental.
    CATO_PREFIX_LENGTHS = (19..32).freeze

    register "cato_pop_html" do |body|
      cidrs = body.scan(%r{\b(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\b}).uniq.select do |cidr|
        length = cidr.split("/").last.to_i
        next false unless CATO_PREFIX_LENGTHS.cover?(length)

        begin
          IPAddr.new(cidr).ipv4?
        rescue StandardError
          false
        end
      end
      unless (30..200).cover?(cidrs.length)
        raise ParseError, "cato_pop_html: #{cidrs.length} CIDRs, expected 30..200 — page changed?"
      end

      cidrs
    end

    # --- documentation-as-data: clouds that publish ranges only in docs -------
    #
    # Three big hosters (Scaleway, IBM Cloud Classic, OVHcloud shared
    # hosting) never built an ip-ranges endpoint; the authoritative list is
    # a page in their documentation. All three now serve that page as raw
    # markdown from their own domain — an LLM-era docs-platform feature that
    # happens to be the cleanest machine path they have. Markdown is a
    # weaker contract than JSON, so each of these parsers is strict about
    # the ONE structure it reads and raises on anything else: a silent
    # rewrite must become keep_stale, never a wrong answer.

    # Scaleway https://www.scaleway.com/en/docs/account/reference-content/
    # scaleway-network-information.md — MDX with a single authoritative
    # section:
    #
    #   ## IP ranges used by Scaleway
    #   ### IPv4
    #   * `62.210.0.0/16`
    #
    # SCOPE IS THE WHOLE POINT. The very next H2 ("## DNS cache servers and
    # NTP servers") lists BARE resolver addresses in the same bullet style,
    # and a later section names the Dedibox monitoring subnet. Only the one
    # section is Scaleway's statement of the space it routes, so we stop
    # dead at the next H2.
    register "scaleway_network_mdx" do |body|
      in_section = false
      cidrs = []
      body.each_line do |line|
        if line.start_with?("## ")
          in_section = line.include?("IP ranges used by Scaleway")
          next
        end
        next unless in_section

        m = line.match(/\A\*\s+`([0-9a-fA-F:.]+\/\d{1,3})`\s*\z/)
        cidrs << m[1] if m
      end
      if cidrs.length < 10
        raise ParseError, "scaleway_network_mdx: found #{cidrs.length} CIDRs, expected >= 10 — page changed?"
      end

      cidrs
    end

    # IBM Cloud Classic https://cloud.ibm.com/docs/infrastructure-hub?topic=
    # infrastructure-hub-ibm-cloud-ip-ranges&format=markdown
    #
    # 759 CIDRs, of which 509 are RFC1918. Ingesting this document whole
    # would label every home and office LAN on earth as IBM hosting, so the
    # parser is defensive twice over:
    #
    #   1. SECTION ALLOWLIST — only "Front-end (public) network", "Load
    #      balancer IPs" and "Legacy networks" are public IBM space. The
    #      back-end, service network and SSL VPN sections are RFC1918; the
    #      "Red Hat Enterprise Linux server requirements" and "Windows
    #      virtual server instance requirements" sections list endpoints a
    #      CUSTOMER must reach (Red Hat, Microsoft WSUS) and must never be
    #      attributed to IBM.
    #   2. RFC1918 GUARD — applied anyway, so a renamed heading degrades to
    #      "too few rows" rather than to a catastrophe.
    #
    # "Legacy networks" is in the allowlist on evidence, not on faith: its
    # rows are ex-ThePlanet/SoftLayer space and ARIN still answers IBM for
    # them (checked 2026-09-12 — 209.85.4.0 → NETBLK-THEPLANET-BLK-EV1-15,
    # registrant "IBM Cloud"; 12.96.160.0 → SOFTLAYER TECHNOLOGIES, INC).
    #
    # Row shape is `|dal05|Dallas |50.23.203.0/24  \n 108.168.157.0/24|`
    # where that `\n` is a LITERAL backslash-n inside one line, not a
    # newline: several data centers pack multiple CIDRs into one cell. The
    # legacy table has a single column and one row is a bare address.
    IBM_PUBLIC_SECTIONS = ["Front-end (public) network", "Load balancer IPs", "Legacy networks"].freeze
    RFC1918 = [IPAddr.new("10.0.0.0/8"), IPAddr.new("172.16.0.0/12"), IPAddr.new("192.168.0.0/16")].freeze

    register "ibm_cloud_ip_ranges_markdown" do |body|
      in_section = false
      cidrs = []
      body.each_line do |line|
        if line.start_with?("## ")
          heading = line.sub(/\A##\s*/, "").strip
          in_section = IBM_PUBLIC_SECTIONS.include?(heading)
          next
        elsif line.start_with?("### ")
          in_section = false # subsections of a public section are never public
          next
        end
        next unless in_section && line.start_with?("|")

        # 3-column tables put the ranges in column 3; the single-column
        # legacy table puts them in column 1. Scan every cell and let the
        # CIDR shape decide — header and separator rows never match.
        line.split("|").each do |cell|
          cell.split(/\s*\\n\s*/).each do |token|
            t = token.strip
            next unless t.match?(%r{\A\d{1,3}(\.\d{1,3}){3}(/\d{1,2})?\z})

            t += "/32" unless t.include?("/")
            addr = begin
              IPAddr.new(t)
            rescue StandardError
              nil
            end
            next if addr.nil? || RFC1918.any? { |p| p.include?(addr) }

            cidrs << t
          end
        end
      end
      cidrs.uniq!
      if cidrs.length < 50
        raise ParseError, "ibm_cloud_ip_ranges_markdown: #{cidrs.length} public CIDRs, expected >= 50 — page changed?"
      end

      cidrs
    end

    # OVHcloud https://docs.ovhcloud.com/en/guides/web-cloud/web-hosting/
    # clusters-and-shared-hosting-ip.md — 24 shared-hosting clusters, each
    # with a per-country VIP table plus two fenced ```bash blocks holding a
    # shared-CDN address and, crucially, the cluster's OUTGOING gateway.
    #
    # The 24 gateways are the valuable half: every PHP script on a cluster —
    # thousands of tenant sites — makes its outbound requests from one of
    # them, so a request a site receives from 91.134.248.230 is by
    # construction server-side automation. (High tenancy is the flip side:
    # consumers must not treat one of these as identifying a single actor.)
    # The table VIPs are inbound-only but are equally OVH datacenter space,
    # so we take both and emit every address as a host route.
    #
    # Read structurally rather than by bare regex: OVH's sibling docs cite
    # third-party endpoints, and IBM's page above is the cautionary tale.
    register "ovh_web_hosting_cluster_md" do |body|
      tokens = []
      pending_fenced_ip = false
      in_fence = false
      body.each_line do |line|
        stripped = line.strip
        if stripped.start_with?("```")
          in_fence = !in_fence
          pending_fenced_ip = false unless in_fence
          next
        end
        if in_fence
          tokens << "#{stripped}/32" if pending_fenced_ip && stripped.match?(/\A\d{1,3}(\.\d{1,3}){3}\z/)
          next
        end
        if stripped.include?("outgoing IP address") || stripped.include?("Shared CDN")
          pending_fenced_ip = true
          next
        end
        next unless stripped.start_with?("|")

        cells = stripped.split("|").map(&:strip)
        # | Country | Country Code | IPv4 | IPv6 | -> ["", country, cc, v4, v6]
        next unless cells.length >= 5 && cells[2].match?(/\A[A-Z]{2}\z/)

        tokens << "#{cells[3]}/32" if cells[3].match?(/\A\d{1,3}(\.\d{1,3}){3}\z/)
        tokens << "#{cells[4]}/128" if cells[4].match?(/\A[0-9a-fA-F:]+\z/) && cells[4].include?("::")
      end
      tokens.uniq!
      if tokens.length < 100
        raise ParseError, "ovh_web_hosting_cluster_md: #{tokens.length} addresses, expected >= 100 — page changed?"
      end

      tokens
    end

    # Broadcom / Symantec Cloud SWG (ex-Web Security Service) service points.
    # Broadcom's own docs name this URL in prose for firewall configuration,
    # which makes it the same shape of publication as Zscaler's CENR feed.
    #
    # The document mixes FOUR different container shapes, which is the whole
    # difficulty:
    #   wss_datapath[].ingress_egress_ranges[]      -> [{range, go_live_date, shutdown_date}]
    #   wss_datapath[].ingress_egress_ranges_ipv6[] -> same, and ABSENT on most entries
    #   wss_egress_routing[].{dedicated,shared}_egress_ranges[].ranges[] -> flat strings
    #   wss_kps[].country_egress_ranges[].ranges[]  -> flat strings with NO prefix
    #   web_isolation[].ranges[]                    -> [{range, …}] again
    #
    # SKIPPED on purpose: `wss_management` (portal/API service hosts such as
    # ctc.threatpulse.com — infrastructure Broadcom runs, not customer
    # browsing egress) and `wss_datapath[].ingress_ips` (tunnel listener
    # addresses already inside the same site's ranges).
    #
    # A range with a PAST shutdown_date is dropped; a future one is kept,
    # because Broadcom announces retirements weeks ahead and that space is
    # still carrying traffic today.
    # Every "*_ranges" (and plain "ranges") key in an allowed section is
    # range data whatever Broadcom calls it, so new region keys are picked up
    # without a gem release. "ips"/"ingress_ips" are deliberately not.
    BROADCOM_RANGE_KEY = /(\A|_)ranges(_ipv6)?\z/.freeze

    register "broadcom_servicepoints_json" do |body|
      data = JSON.parse(body)
      raise ParseError, "broadcom_servicepoints_json: expected object" unless data.is_a?(Hash)

      now = Time.now.utc
      retired = lambda do |entry|
        stamp = entry["shutdown_date"]
        return false unless stamp.is_a?(String)

        begin
          Time.parse("#{stamp} UTC") < now
        rescue StandardError
          false
        end
      end

      tokens = []
      %w[wss_datapath wss_egress_routing wss_kps web_isolation].each do |section|
        Array(data[section]).each do |site|
          next unless site.is_a?(Hash)

          site.each do |key, value|
            next unless key.match?(BROADCOM_RANGE_KEY)

            Array(value).each do |entry|
              case entry
              when Hash
                # Either {range, shutdown_date} or a country group {ranges: [...]}.
                next if retired.call(entry)

                tokens << entry["range"] if entry["range"].is_a?(String)
                Array(entry["ranges"]).each { |r| tokens << r if r.is_a?(String) }
              when String
                tokens << entry
              end
            end
          end
        end
      end

      # wss_kps publishes bare addresses ("168.149.168.0"); make them host routes.
      tokens = tokens.map { |t| t.include?("/") ? t : "#{t}/#{t.include?(':') ? 128 : 32}" }.uniq
      if tokens.length < 300
        raise ParseError, "broadcom_servicepoints_json: #{tokens.length} ranges, expected >= 300 — schema changed?"
      end

      tokens
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
      tokens = xml_tag_attributes(body, "server").filter_map do |attrs|
        next unless attrs["visible"].to_s == "1" && attrs["status"].to_s == "1"

        ip = attrs["ip"].to_s.strip
        ip unless ip.empty?
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
      tokens = body.scan(%r{<td\b[^>]*>(.*?)</td>}im).flat_map do |cell|
        # Some first-party support tables split hostnames across inline tags,
        # e.g. `ca1.<span>vpn.giganews.com</span>`. Strip markup inside each
        # cell before scanning so the parser stays generic without scraping
        # arbitrary hostnames from the whole page chrome.
        text = cell.first.to_s.dup.force_encoding(Encoding::UTF_8).scrub
                   .gsub(/<[^>]*>/, "").gsub(/&nbsp;|&#160;/i, " ").tr("\u00A0", " ")
        text.scan(/\b[a-z0-9.-]+\.[a-z]{2,63}\b/i)
      end.map(&:downcase)
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

    register "worldvpn_servers_html" do |body|
      # WorldVPN's public server table gives exact IPs next to
      # *.ocservvpn.com hostnames. Keep this parser table-shaped instead of
      # doing a whole-page IP scrape; WordPress/CSS assets can contain
      # version-looking strings that must not become VPN evidence.
      tokens = body.scan(/<tr\b.*?<\/tr>/mi).filter_map do |row|
        cells = row.scan(/<td\b[^>]*>(.*?)<\/td>/mi).flatten.map { |cell| strip_html(cell) }
        ip = cells[1].to_s
        host = cells[2].to_s.downcase
        next unless ip.match?(/\A(?:\d{1,3}\.){3}\d{1,3}\z/) && host.match?(/\A[a-z]{2}\d+\.ocservvpn\.com\z/)

        ip
      end
      raise ParseError, "worldvpn_servers_html: no server IPs — schema changed?" if tokens.empty?

      tokens.uniq
    end

    # OVPN's client bootstrap API: the whole fleet in ONE request, where the
    # status-page recipe it replaces needed thirty-two (one per datacenter).
    # Shape: {"success": true, "datacenters": [{"slug", "city",
    # "ping_address", "pools": [...], "servers": [{"ip", "ptr", "online", …}]}],
    # "shadowsocks": {…}}.
    #
    # Two deliberate choices. We do NOT filter on `online`: a server that is
    # briefly down is still OVPN's egress address and dropping it would make
    # the overlay flap. And we read only `datacenters` — the sibling
    # `shadowsocks` object carries a shared credential, so nothing outside
    # `datacenters` is touched and the raw body must never be logged.
    register "ovpn_client_entry_json" do |body|
      data = JSON.parse(body)
      raise ParseError, "ovpn_client_entry_json: success != true — API changed?" unless data["success"] == true

      centers = data["datacenters"]
      raise ParseError, "ovpn_client_entry_json: expected datacenters array" unless centers.is_a?(Array)

      tokens = centers.flat_map do |center|
        next [] unless center.is_a?(Hash)

        servers = center["servers"].is_a?(Array) ? center["servers"] : []
        [center["ping_address"]] + servers.map { |s| s["ip"] if s.is_a?(Hash) }
      end.compact.uniq
      raise ParseError, "ovpn_client_entry_json: no server IPs — schema changed?" if tokens.empty?

      tokens
    end

    register "ovpn_status_servers_json" do |body|
      data = JSON.parse(body)
      rows = data["data"]
      raise ParseError, "ovpn_status_servers_json: expected data array" unless rows.is_a?(Array)

      tokens = rows.filter_map do |server|
        next if server["online"] == false

        server["ip"]
      end
      raise ParseError, "ovpn_status_servers_json: no online server IPs — schema changed?" if tokens.empty?

      tokens.uniq
    end

    register "anonine_status_json" do |body|
      data = JSON.parse(body)
      raise ParseError, "anonine_status_json: expected array" unless data.is_a?(Array)

      tokens = data.flat_map do |row|
        server_ips = (row["servers"] || []).flat_map { |server| server["ips"] || [] }
        [row["primary_ip"], *server_ips]
      end.compact
      raise ParseError, "anonine_status_json: no server IPs — schema changed?" if tokens.empty?

      tokens.uniq
    end

    register "azirevpn_locations_json" do |body|
      data = JSON.parse(body)
      rows = data["locations"]
      raise ParseError, "azirevpn_locations_json: expected locations array" unless rows.is_a?(Array)

      tokens = rows.filter_map { |location| location["pool"] }
      raise ParseError, "azirevpn_locations_json: no pool hostnames — schema changed?" if tokens.empty?

      tokens.uniq
    end

    register "vpnac_status_html" do |body|
      tokens = body.scan(%r{<td\b[^>]*>\s*([a-z0-9][a-z0-9.-]*\.vpn\.ac)\s*</td>}i)
                   .flatten
                   .map(&:downcase)
      raise ParseError, "vpnac_status_html: no status table hostnames — schema changed?" if tokens.empty?

      tokens.uniq
    end

    register "trustzone_servers_html" do |body|
      tokens = body.scan(/\b[a-z0-9]+(?:-[a-z0-9]+)*\.trust\.zone\b/i)
                   .map(&:downcase)
                   .reject { |host| host == "www.trust.zone" || host == "trust.zone" }
      raise ParseError, "trustzone_servers_html: no Trust.Zone server hostnames — schema changed?" if tokens.empty?

      tokens.uniq
    end

    # SlickVPN redesigned https://www.slickvpn.com/locations/ between
    # 2026-07-05 and 2026-09-05: the old "hostname printed inside the .ovpn
    # link text" markup is gone and each location card now carries an
    # explicit copy-to-clipboard button, `<button data-host="gw1.bos1.
    # slickvpn.com" title="Copy server address">`, next to an "Active" badge.
    # Reading data-host is both simpler and stricter than the old pairing
    # heuristic — it is the exact server address SlickVPN tells its own
    # users to connect to, with no inference.
    register "slickvpn_locations_html" do |body|
      tokens = body.scan(/data-host=["']([a-z0-9.-]+\.slickvpn\.com)["']/i).flatten.map(&:downcase)
      raise ParseError, "slickvpn_locations_html: no data-host server addresses — schema changed?" if tokens.empty?

      tokens.uniq
    end

    register "freevpn_us_status_html" do |body|
      allowed = {
        "openvpn" => /\Aovpn-[a-z0-9-]+\.vpnv\.cc\z/i,
        "wireguard" => /\Awireguard-[a-z0-9-]+\.vpnv\.cc\z/i,
        "pptp" => /\Apptp-[a-z0-9-]+\.vpnv\.cc\z/i
      }

      tokens = body.scan(/<tr\b[^>]*>/i).filter_map do |tag|
        type = tag[/\bdata-type=["']([^"']+)["']/i, 1].to_s.downcase
        host = tag[/\bdata-host=["']([^"']+)["']/i, 1].to_s.downcase
        pattern = allowed[type]
        host if pattern && host.match?(pattern)
      end
      raise ParseError, "freevpn_us_status_html: no VPN hosts — schema changed?" if tokens.empty?

      tokens.uniq
    end

    class << self
      private

      def strip_html(fragment)
        fragment.gsub(/<[^>]+>/, " ")
                .gsub(/&nbsp;|&#160;/i, " ")
                .gsub(/\s+/, " ")
                .strip
      end

      # Tiny tag-attribute scanner for provider XML-ish feeds. We only need
      # exact attributes from a trusted source-specific tag; pulling in REXML
      # would make production apps depend on a bundled gem that Ruby 3.4 no
      # longer guarantees is installed.
      def xml_tag_attributes(body, tag_name)
        body.scan(/<#{Regexp.escape(tag_name)}\b[^>]*>/i).map do |tag|
          attrs = {}
          tag.scan(/\b([a-z_:][\w:.-]*)\s*=\s*(["'])(.*?)\2/im).each do |key, _quote, value|
            attrs[key.downcase] = value
          end
          attrs
        end
      end

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
