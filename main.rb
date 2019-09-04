require 'net/http'
require 'rexml/document'
require 'resolv'
require 'utils'

class Dynadot
  BASE_URI = URI("https://api.dynadot.com/api3.xml").freeze

  def initialize(key, dry_run: false, log:)
    @key, @dry_run, @log = key, dry_run, log
  end

  def set_dns2(main_records: [], subdomains: [], **opts)
    request(build_args("set_dns2") { |h|
      h.update index_args(
        main_records.map { |typ, *rest| [typ.downcase, *rest] },
        %i( main_record_type main_record main_recordx ),
      )
      h.update index_args(
        subdomains.map { |s, typ, *rest| [s, typ.downcase, *rest] },
        %i( subdomain sub_record_type sub_record sub_recordx ),
      )
      h.update opts
    })
  end

  private def index_args(arr, keys)
    args = {}
    arr.each_with_index do |values, idx|
      keys.zip(values) do |key, val|
        args[:"#{key}#{idx}"] = val if val
      end
    end
    args
  end

  private def build_args(command, &block)
    args = {}.tap &block
    args.update \
      COMMAND_PARAM => command,
      "key" => @key
    args.transform_keys! &:to_s
    args.transform_values! &:to_s
  end

  COMMAND_PARAM = "command".freeze
  
  private def request(args)
    log = @log
    if cmd = args[COMMAND_PARAM]
      log = log[cmd]
    end
    log[args: args].debug "about to send command request"

    uri = BASE_URI.dup.tap { |u| u.query = URI.encode_www_form args }
    xml = log[args: args.size].info "sending command request" do
      if @dry_run
        next %(
          <SetDnsResponse>
            <SetDnsHeader>
              <SuccessCode>0</SuccessCode>
              <Status>success</Status>
            </SetDnsHeader>
          </SetDnsResponse>
        )
      end
      Timeout.timeout(10) { Net::HTTP.get_response(uri) }.
        tap { |r| Net::HTTPSuccess === r or raise "unexpected response: #{r}" }.
        body
    end

    if exc = Result.new(xml).exception
      raise exc
    end
  end

  class Result < Struct.new :ok, :status, :error, keyword_init: true
    class InvalidXMLError < StandardError; end

    def initialize(xml)
      ##
      # Example XML:
      #
      #   <SetDnsResponse>
      #     <SetDnsHeader>
      #       <SuccessCode>0</SuccessCode>
      #       <Status>success</Status>
      #     </SetDnsHeader>
      #   </SetDnsResponse>
      #
      h = Hash[REXML::Document.new(xml).yield_self { |doc|
        hd = doc.root.children.find { |e|
          REXML::Element === e && e.name =~ /Header$/
        } or raise InvalidXMLError
        hd.children.grep(REXML::Element).map { |e| [e.name, e.text] }
      }]
      super \
        ok: h.fetch("SuccessCode") == "0",
        status: h.fetch("Status"),
        error: h["Error"]
    end

    def exception
      RuntimeError.new "%s: %p" % [status, error] if !ok
    end
  end
end

module PublicIP
  def self.get
    JSON.
      parse(Net::HTTP.get(URI("https://api.myip.com"))).
      fetch("ip").
      tap { |s| valid_ipv4? s or raise "invalid public IPv4" }
  end

  def self.valid_ipv4?(s)
    ip = begin
      IPAddr.new s
    rescue IPAddr::InvalidAddressError
      return false
    end
    ip.ipv4? && !ip.private?
  end
end

module SubdomainUpdate
  def self.update(sub, domain, dns_args, dynadot:, log:)
    ip = log.debug "getting public IP" do
      PublicIP.get
    end
    log[ip: ip].info "got public IP"

    sub_fqdn = "#{sub}.#{domain}"
    current = log.debug "getting current DNS value" do
      Resolv::DNS.new.getaddress(sub_fqdn).to_s
    rescue Resolv::ResolvError
      nil
    end
    log[sub: sub_fqdn, current: current.inspect].info "got current DNS value"

    if current == ip
      log.info "DNS record already up to date"
      return
    end
    log.info "DNS record out of date, updating"

    dns_args = dns_args.merge \
      subdomains: (dns_args[:subdomains] || []).
        reject { |name, typ| name == sub && typ == "A" } + [
          [sub, "A", ip]
        ]

    dynadot.set_dns2 domain: domain, **dns_args
    log.info "DNS record updated"
  end
end

if $0 == __FILE__
  dry_run = ARGV.delete "--dry_run"
  ARGV.empty? or raise "usage: #{File.basename $0} [--dry_run]"

  log = Utils::Log.new $stdout
  dynadot = Dynadot.new File.read("api_key").strip,
    dry_run: dry_run,
    log: log["Dynadot"]

  SubdomainUpdate.update "home", "romanlenegrate.net", {
    main_records: [
      ["A", "185.199.108.153"],
      ["MX", "aspmx.l.google.com", 1],
      ["MX", "alt1.aspmx.l.google.com", 5],
      ["MX", "alt2.aspmx.l.google.com", 5],
      ["MX", "alt3.aspmx.l.google.com", 10],
      ["MX", "alt4.aspmx.l.google.com", 10],
      ["A", "185.199.109.153"],
      ["A", "185.199.110.153"],
      ["A", "185.199.111.153"],
    ],
    ttl: 3600,
  }, {
    dynadot: dynadot,
    log: log,
  }
end
