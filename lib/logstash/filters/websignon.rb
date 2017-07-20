# encoding: utf-8
require 'logstash/filters/base'
require 'logstash/namespace'
require 'lru_redux'
require 'httpclient'

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

  # The name of the container to put all of the user attributes into.
  #
  # If this setting is omitted, attributes will be written to the root of the
  # event, as individual fields.
  config :target, :validate => :string 

  public
  def register
    if @hit_cache_size > 0
      @hit_cache = LruRedux::TTL::ThreadSafeCache.new(@hit_cache_size, @hit_cache_ttl)
    end

    if @failed_cache_size > 0
      @failed_cache = LruRedux::TTL::ThreadSafeCache.new(@failed_cache_size, @failed_cache_ttl)
    end

    @http = HTTPClient.new({ :agent_name => 'Logstash', :connect_timeout => @websignon_timeout})
    # disable cookie storage
    @http.cookie_manager = nil
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
        
      rescue LogStash::Filters::Websignon::ConnectionError, SocketError, OpenSSL::SSL::SSLError, HTTPClient::TimeoutError => e
        @logger.error('Websignon Connection Error', :error => e)

    end
  end # def websignon_lookup

  private
  def do_lookup(username)
    response = @http.get(@websignon_url,:query => { :requestType => 4, :user => username })
    if response.status == 200 && !response.body.nil? 
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
