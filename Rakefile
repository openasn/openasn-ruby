# frozen_string_literal: true

require "bundler/gem_tasks"
require "rake/testtask"

Rake::TestTask.new(:test) do |t|
  t.libs << "test"
  t.libs << "lib"
  t.test_files = FileList["test/**/*_test.rb"]
end

desc "Refresh the bundled data seed from the latest OpenASN release (run before each gem release)"
task "seed:refresh" do
  require "open-uri"
  require "fileutils"
  base = ENV.fetch("OPENASN_RELEASE_URL", "https://github.com/openasn/openasn/releases/download/latest/") # tag-addressed, badge-immune: see Configuration#release_url
  seed = File.expand_path("lib/openasn/data/seed", __dir__)
  FileUtils.mkdir_p(seed)
  # ATTRIBUTION.md travels with the bins: the gem redistributes them, and the
  # backbone is RouteViews-derived (CC BY 4.0) plus MIT inputs whose notices
  # must accompany copies (data repo DECISIONS.md D-SRC-2 (backbone) item 5).
  # The seed carries no orgs file on purpose: Snapshot reads openasn-orgs.bin
  # only from data_dir, so a fresh install has as_org nil until its first update.
  files = %w[openasn-ipv4.bin openasn-ipv6.bin manifest.json fetch-manifest.json ATTRIBUTION.md]
  fetched = files.to_h do |f|
    puts "downloading #{f}…"
    URI.open("#{base}#{f}", "User-Agent" => "openasn-seed-refresh") { |io| [f, io.read] } # rubocop:disable Security/Open
  end
  # Verify everything against the release's own manifest before writing a byte.
  require "json"
  require "digest"
  expected = JSON.parse(fetched["manifest.json"]).fetch("files").to_h { |e| [e["name"], e["sha256"]] }
  (files - ["manifest.json"]).each do |f|
    actual = Digest::SHA256.hexdigest(fetched[f])
    abort "seed:refresh: #{f} sha256 #{actual} != manifest #{expected[f].inspect}" unless actual == expected[f]
  end
  fetched.each { |f, bytes| File.binwrite(File.join(seed, f), bytes) }
  puts "verified #{files.size - 1} files against manifest.json (build #{JSON.parse(fetched["manifest.json"])["build_id"]})"
  puts "seed refreshed — remember: gem versions ship on CODE changes; data freshness flows through releases + UpdateJob, never through gem releases"
end

desc "Benchmark lookup latency against the bundled seed (RUN_BENCH=1 rake bench)"
task :bench do
  ENV["RUN_BENCH"] = "1"
  ruby "-Ilib", "-Itest", "test/bench.rb"
end

task default: :test
