# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"
require "lru_redux"

class LogStash::Filters::Websignon < LogStash::Filters::Base

  config_name "websignon"

  # set the websignon lookup url
  config :websignon_url, :validate => :string, :required => true

  # set the websignon lookup timeout
  config :websignon_timeout, :validate => :number, :default => 30

  # field that contains the username to lookup
  config :username_field, :validate => :string, :required => true

  # set the size of cache for successful requests
  config :hit_cache_size, :validate => :number, :default => 0

  # how long to cache successful requests (in seconds)
  config :hit_cache_ttl, :validate => :number, :default => 86400

  # cache size for failed requests
  config :failed_cache_size, :validate => :number, :default => 0

  # how long to cache failed requests (in seconds)
  config :failed_cache_ttl, :validate => :number, :default => 60

  # which attributes are wanted
  config :attributes, :validate => :array, :default => ["firstname","lastname","dept"]

#  config :target, :validate => :string, :default =>

  public
  def register
    if @hit_cache_size > 0
      @hit_cache = LruRedux::TTL::ThreadSafeCache.new(@hit_cache_size, @hit_cache_ttl)
    end

    if @failed_cache_size > 0
      @failed_cache = LruRedux::TTL::ThreadSafeCache.new(@failed_cache_size, @failed_cache_ttl)
    end
  end # def register

  public
  def filter(event)

    return if websignon_lookup(event).nil?
    
    filter_matched(event)
  end # def filter

  private
  def websignon_lookup(event)
    username = event.get(@username_field)
    
    @logger.debug? && @logger.debug("Looking up user", :username => username)

    begin
      return nil if @failed_cache && @failed_cache.key?(username) # recently failed lookup, skip

      if @hit_cache
        user_attributes = @hit_cache.fetch(username) { do_lookup(username) }
      else
        user_attributes = do_lookup(username)
      end

      # cache results
      if user_attributes.nil?
        @failed_cache[username] = nil if @failed_cache
        return nil
      else
        @hit_cache[username] = user_attributes if @hit_cache
      end

      @attributes.each do |attribute|
        event.set(attribute,user_attributes[attribute])
      end

      rescue Net::OpenTimeout,Net::ReadTimeout
        @logger.error("Websignon connection timeout", :username => username, :websignon_url => @websignon_url)
    end
  end # def websignon_lookup

  private
  def do_lookup(username)

    uri = URI.parse(@websignon_url)
    params = {:requestType => 4, :user => username}
    uri.query = URI.encode_www_form(params)
    Net::HTTP.get_response(uri) do |response|
      if !response.body.nil?
        hash = {}
        response.body.split(/\n/).each do |kv|
          attrs = kv.split(/=/,2)
          hash[attrs[0]] = attrs[1]
        end

        if !hash["returnType"].nil? && hash["returnType"] != 54
          @logger.debug? && @logger.debug("Found user", :username => username)
          return hash
        else
          @logger.debug? && @logger.debug("User not found", :username => username)
          return nil
        end
      end
    end
  end # def do_lookup

  private
  def to_uri(url)
    begin
      if !url.kind_of?(URI)
        return URI.parse(url)
      end
      rescue URI::InvalidURIError
        @logger.error("Invalid websignon url", :url => url)
    end
  end # def to_uri

end # class LogStash::Filters::Websigon
