require 'optparse'
require 'thread'

# no argv, print usage
ARGV.push('-h') if ARGV.empty?

options = {}
# ruby optag(like c)
OptionParser.new do |parser|

  parser.banner = "Usage: ruby ab_auto.rb [options]"
  parser.on('-r', '--req REQUEST', 'Number of requests to perform for the benchmarking session.') do |r|
    options[:request] = r
  end

  parser.on('-c', '--con CONCURRENCY', 'Number of multiple requests to perform at a time.') do |c|
    options[:thread] = c
  end

  parser.on('-u', '--url URL', 'URI for test.') do |u|
    options[:url] = u
  end

  parser.on('-n', '--ntimes NTIMES', 'Number of repeat test.') do |n|
    options[:num] = n
  end

  parser.on_tail('-h', '--help', 'Help of usage.') do
    puts parser
    exit
  end

end.parse!

# do work ab(apache benchmarking)
def ab_test(nRequest, nThread, uri)
  res = %x(ab -n #{nRequest} -c #{nThread} #{uri})
  return res.match(/(?<=Time taken for tests:).*(?=seconds)/).to_s.to_f, res.match(/(?<=Time per request:).*(?=\[ms\] \(mean\))/).to_s.to_f
end

# using thread
puts "Begining of test..."
sum_tt = 0;
sum_mt = 0;
tarr = []
if options[:num]
  options[:num].to_s.to_i.times do |i|
    tarr[i] = Thread.new do
      test_time, mean_time = ab_test(options[:request], options[:thread], options[:url])
      puts "Thread #{i} test_time: #{test_time}"
      puts "Thread #{i} mean_time: #{mean_time}"
      sum_tt += test_time
      sum_mt += mean_time
    end
  end
end

tarr.each {|t| t.join}
av_tt = sum_tt / options[:num].to_s.to_i
av_mt = sum_mt / options[:num].to_s.to_i
puts "-===[ average of #{options[:num]} times test ]===-"
puts "average of time taken: #{av_tt} seconds"
puts "average of time per request: #{av_mt} ms(milliseconds)"
