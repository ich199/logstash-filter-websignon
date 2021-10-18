# encoding: utf-8
require 'logstash/filters/base'
require 'logstash/namespace'
require 'lru_redux'
require 'manticore'

class LogStash::Filters::Websignon < LogStash::Filters::Base

  config_name 'websignon'
  require 'logstash/filters/websignon/websignon_exceptions'

  # websignon lookup url
  config :websignon_url, :validate => :string, :required => true

  # websignon connection/lookup timeout (in seconds)
  config :websignon_timeout, :validate => :number, :default => 5

  # Event field that contains the username to lookup
  config :username_field, :validate => :string, :required => true

  # Cache size for known username attributes
  config :hit_cache_size, :validate => :number, :default => 0

  # How long to cache known username attributes (in seconds), default 86400 = 24 hours
  config :hit_cache_ttl, :validate => :number, :default => 86400

  # Cache size for unknown usernames
  config :failed_cache_size, :validate => :number, :default => 0

  # How long to cache unknown usernames (in seconds), default 3600 = 1 hour
  config :failed_cache_ttl, :validate => :number, :default => 3600

  # Array of user attributes that should be added to the event
  config :attributes, :validate => :array, :default => ['firstname','lastname','dept']

  # Tag to apply when no such user is found in websignon
  config :tag_on_nouser, :validate => :array, :default => ['_websignonnosuchuser']

  # TLS version for connecting to websignon
  config :ssl_versions, :validate => :array, :default => ['TLSv1.2']

  # TLS Ciphers for connecting to websignon (Java/IANA style cipher names)
  config :ciphers, :validate => :array, :default => ['TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256','TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256','TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384','TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384']

  # The name of the container to put all of the user attributes into.
  #
  # If this setting is omitted, attributes will be written to the root of the
  # event, as individual fields.
  config :target, :validate => :string 

  # Additional request headers to be sent to websignon
  config :request_headers, :validate => :array, :default => [['Accept-Charset','utf-8']]

  public
  def register
    if @hit_cache_size > 0
      @hit_cache = LruRedux::TTL::ThreadSafeCache.new(@hit_cache_size, @hit_cache_ttl)
    end

    if @failed_cache_size > 0
      @failed_cache = LruRedux::TTL::ThreadSafeCache.new(@failed_cache_size, @failed_cache_ttl)
    end
    @http = Manticore::Client.new({:user_agent => 'Logstash',
                                   :connect_timeout => @websignon_timeout,
                                   :keepalive => false,
                                   :ssl => {
                                     :cafile => '/etc/pki/tls/certs/ca-bundle.crt',
                                     :protocols => @ssl_versions,
                                     :cipher_suites => @ciphers
                                   }
                                  })
  end # def register

  public
  def filter(event)

    return if websignon_lookup(event).nil?
    
    filter_matched(event)
  end # def filter

  private
  def websignon_lookup(event)
    username = event.get(@username_field)
    
    @logger.debug? && @logger.debug('Looking up user', :username => username)

    begin

      if (@failed_cache && @failed_cache.key?(username)) || username=='' || username=='-' || username.nil? 
        # recently failed lookup or missing username, skip
        @tag_on_nouser.each do |tag|
          event.tag(tag) if !(username=='' || username=='-' || username.nil?)
        end
        return nil
      end

      if @hit_cache
        user_attributes = @hit_cache.fetch(username) { do_lookup(username) }
      else
        user_attributes = do_lookup(username) if !(username=='-' || username=='')
      end

      #cache results
      @hit_cache[username] = user_attributes if @hit_cache && !user_attributes.nil?
      if @target
        @attributes.each do |attribute|
          event.set("[#{@target}][#{attribute}]", user_attributes[attribute]) if !user_attributes[attribute].nil?
        end
      else 
        @attributes.each do |attribute|
          event.set(attribute,user_attributes[attribute]) if !user_attributes[attribute].nil?
        end
      end

      rescue LogStash::Filters::Websignon::NoSuchUser => e
        @failed_cache[username] = nil if @failed_cache
        @tag_on_nouser.each do |tag|
          event.tag(tag)
        end
        @logger.error('No such user found', :username => e.message)

      rescue LogStash::Filters::Websignon::ConnectionError, Manticore::Timeout, Manticore::SocketException, Manticore::ClientProtocolException, Manticore::ResolutionFailure, SocketError, OpenSSL::SSL::SSLError, Errno::ECONNREFUSED => e
        @logger.error('Websignon Connection Error', :error => e)

    end
  end # def websignon_lookup

  private
  def do_lookup(username)
    response = @http.post(@websignon_url,:params => { :requestType => 4, :user => username }, :headers => @request_headers)
    if response.code == 200 && !response.body.nil? 
      hash = {}
      response.body.split(/\n/).each do |kv|
        attrs = kv.split(/=/,2)
        hash[attrs[0]] = attrs[1]
      end
      if !hash['returnType'].nil? && hash['returnType'] != '54'
        @logger.debug? && @logger.debug('Found user', :username => username)
        return hash
      else
        raise LogStash::Filters::Websignon::NoSuchUser, username
      end
    else
      raise LogStash::Filters::Websignon::ConnectionError, response
    end

  end # def do_lookup

end # class LogStash::Filters::Websigon
