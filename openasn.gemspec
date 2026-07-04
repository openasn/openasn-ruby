# frozen_string_literal: true

require_relative "lib/openasn/version"

Gem::Specification.new do |spec|
  spec.name = "openasn"
  spec.version = OpenASN::VERSION
  spec.authors = ["rameerez"]
  spec.email = ["rubygems@rameerez.com"]

  spec.summary = "Offline IP origin intelligence: classify IPs as residential, mobile, hosting, VPN, Tor, relay — zero API calls"
  spec.description = "OpenASN classifies where an IP address is really coming from — residential ISP, mobile carrier, hosting/datacenter, VPN, Tor exit, iCloud Private Relay, enterprise gateway, business, education, government, CGNAT, or unknown — entirely offline, in microseconds, with zero runtime dependencies and zero API calls. It bundles a seed of the open OpenASN dataset (CC0), refreshes it nightly from GitHub Releases, and layers fast-moving overlays (Tor exits, cloud ranges, Apple Private Relay) fetched by your own server from the original authorities. Verdict-first API with full explainability: every classification is auditable to its source."
  spec.homepage = "https://github.com/openasn/ruby"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 3.1.0"

  spec.metadata["allowed_push_host"] = "https://rubygems.org"

  spec.metadata["rubygems_mfa_required"] = "true"
  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = "https://github.com/openasn/ruby"
  spec.metadata["changelog_uri"] = "https://github.com/openasn/ruby/blob/main/CHANGELOG.md"

  # Specify which files should be added to the gem when it is released.
  # The `git ls-files -z` loads the files in the RubyGem that have been added into git.
  # Note: the bundled data seed (lib/openasn/data/seed/*.bin) IS shipped in
  # the gem on purpose — it is what makes the first boot work offline.
  gemspec = File.basename(__FILE__)
  spec.files = IO.popen(%w[git ls-files -z], chdir: __dir__, err: IO::NULL) do |ls|
    ls.readlines("\x0", chomp: true).reject do |f|
      (f == gemspec) ||
        f.start_with?(*%w[bin/ test/ spec/ features/ .git .github appveyor Gemfile])
    end
  end
  spec.bindir = "exe"
  spec.executables = spec.files.grep(%r{\Aexe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  # ZERO runtime dependencies — a deliberate, load-bearing design decision.
  # Everything runs on stdlib: ipaddr, json, net/http, fileutils, digest,
  # logger, time, tmpdir. Rails/ActiveJob integrations are conditionally
  # defined and never required. Keep it this way.

  # Development dependencies are managed in the Gemfile
end
