# frozen_string_literal: true

source "https://rubygems.org"
gemspec

gem "rake", "~> 13.0"

group :development do
  gem "irb"
  gem "rubocop", "~> 1.0"
  gem "rubocop-minitest", "~> 0.35"
  gem "rubocop-performance", "~> 1.0"
end

group :development, :test do
  gem "minitest", ">= 5.25", "< 7" # 6.x needs Ruby >= 3.2; 5.x keeps the 3.1 CI lane alive
  gem "minitest-reporters", "~> 1.6"
  gem "mocha", "~> 2.0"
  gem "ostruct"
  gem "rack"
  gem "rack-test"
  gem "railties", ">= 7.1" # generator tests only
  gem "simplecov", require: false
  gem "webmock", "~> 3.19"
  gem "benchmark" # stdlib gem-ification (Ruby 3.5+); used by rake bench
end
