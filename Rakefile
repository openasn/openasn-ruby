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
  %w[openasn-ipv4.bin openasn-ipv6.bin manifest.json fetch-manifest.json].each do |f|
    puts "downloading #{f}…"
    URI.open("#{base}#{f}", "User-Agent" => "openasn-seed-refresh") do |io| # rubocop:disable Security/Open
      File.binwrite(File.join(seed, f), io.read)
    end
  end
  puts "seed refreshed — remember: gem versions ship on CODE changes; data freshness flows through releases + UpdateJob, never through gem releases"
end

desc "Benchmark lookup latency against the bundled seed (RUN_BENCH=1 rake bench)"
task :bench do
  ENV["RUN_BENCH"] = "1"
  ruby "-Ilib", "-Itest", "test/bench.rb"
end

task default: :test
