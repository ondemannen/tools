#!/usr/bin/ruby

require 'optparse'
require 'rubygems'
require 'net/dns'

@options = {
	:verbose => false,
	:domain => nil,
	:ns => nil,
}

domains = OptionParser.new do |opts|
	opts.banner = "Usage: #{$0} [@options]"
	opts.on("-l","--list","List one address per line") {|l| @options[:list] = true}
	opts.on("-n","--nameserver IP","Specify which name server to use.") {|n| @options[:ns] = n}
	opts.on("-v","--verbose","Run verbosely") { |v| @options[:verbose] = true }
	opts.on("-h","--help","Show this message") { puts opts; exit 0 }
end.parse!

domains.each do |d|
	domains.delete(d) if !d.match(/[\w\d\.\-\_]+\.[\w\d\.\-\_]+/)
end
if domains.size < 1
	STDERR.puts "Need at least one valid domain name"
	exit 1
end

@dns = Net::DNS::Resolver.new
if @options[:ns]
	p ["DNS Server", @dns.nameservers] if @options[:verbose]
	@dns.nameservers = @options[:ns]
end
def parse_spf_string(str)
	rr = []
	res = {:ip => [], :include => [], :redirect => []}
	s = str.sub(/\A"v=spf1\s+(.*)"\z/,'\1').gsub(/"/,'').split(/\s+/)
	s.each do |r|
		if r.match(/\Aip\d:(.*)\z/i)	
			res[:ip] << $1
		elsif r.match(/\Ainclude:(.*)\z/i)
			res[:include] << $1
			get_spf($1)
		elsif r.match(/\Aredirect=(.*)\z/i)
			res[:redirect] << $1
			get_spf($1)
		else
			rr << r unless r.match(/^(v=spf1|.all)/)
		end
	end
	STDERR.puts rr if rr.size > 0
	res.each do |k,v|
		@res[k] << v
		@res[k].flatten!
	end
	rr
end

def get_spf(v)
	arr = []
	res = []
	answer = @dns.query(v,'txt').answer
	answer.each do |a|
		next unless a.txt.match(/^"?v=spf(1|2)/i)
		printf("%s\n\t%s\n", v, a.txt)
		arr << a.txt
	end
	if arr.size > 1
		STDERR.puts "Not in compliance with RFC. More than one record for #{v} (or just using spf1 and spf2)"
		STDERR.puts arr
		exit 1
	elsif arr.size < 1
		STDERR.puts "No SPF records for #{v}"
		exit 0
	end
	res << parse_spf_string(arr[0]).join(" ")
end

domains.each do |d|
	@res = {:ip => [], :include => [], :redirect => []}
	puts "Doing a recursive check of SPF records for #{d}"
	get_spf(d)
	@res.each do |k,v|
		if v.size > 0 && @options[:list]
			puts k
			v.each {|x| puts "\t#{x}" }
		end
	end
end

exit  0
