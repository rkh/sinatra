require File.dirname(__FILE__) + '/helper'

if defined? RUBY_ENGINE and RUBY_ENGINE == "jruby"
  warn "skipping memory leak tests on JRuby"
else
  class LeakTest < Test::Unit::TestCase
    def measure
      100.times { get('/') }
      GC.start
      ObjectSpace.each_object.count
    end

    it "should not leak objects" do
      mock_app { get('/') { "hi" }}
      measure
      a = measure + 2 # a and b might be Bignums
      b = measure
      assert(b <= a, "#{b - a} new objects")
    end
  end
end
