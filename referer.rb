require "logstash/filters/base"
require "logstash/namespace"
require "tempfile"

# Parse referer strings into structured data based on snowplow data
# 
# Referer filter, adds information about referer source, provider, etc 
# once the original gem gets its internal API updated more fileds & 
# providers will be added.
#
# fork version used: https://github.com/tombar/referer-parser 
#
# Logstash releases ship with the referers.yaml database made available from
# referer-parser with an Apache 2.0 license. For more details on referer-parser, see
# <https://github.com/snowplow/referer-parser>.
class LogStash::Filters::Referal < LogStash::Filters::Base
  config_name "referal"
  plugin_status "experimental"

  # The field containing the referer string. If this field is an
  # array, only the first value will be used.
  config :source, :validate => :string, :required => true

  # The name of the field to assign the referer data hash to
  config :target, :validate => :string, :default => "referal"

  # referers.yaml file to use
  #
  # If not specified, this will default to the referers.yaml that ships
  # with logstash.
  config :referers_file, :validate => :string

  public
  def register
    require 'referer-parser'
    if @referers_file.nil?
      begin
        @parser = RefererParser::Referer.new('http://logstash.net')
      rescue Exception => e
        begin
          if __FILE__ =~ /file:\/.*\.jar!/
            # Running from a flatjar which has a different layout
            referers_file = [__FILE__.split("!").first, "/vendor/referer-parser/data/referers.yaml"].join("!")
            @parser = RefererParser::Referer.new('http://logstash.net', referers_file)
          else
            # assume operating from the git checkout
            @parser = RefererParser::Referer.new('http://logstash.net', "vendor/referers_file/referers.yaml")
          end
        rescue => ex
          raise "Failed to cache, due to: #{ex}\n#{ex.backtrace}"
        end
      end
    else
      @logger.info("Using referer-parser with external referers.yml", :referers_file => @referers_file)
      @parser = RefererParser::Referer.new('http://logstash.net', @referers_file) 
    end
  end #def register

  public
  def filter(event)
    return unless filter?(event)
    referal_data = nil

    referer = event[@source]
    referer = referer.first if referer.is_a? Array

    begin
      referal_data = @parser.parse(referer)
    rescue Exception => e
      @logger.error("Uknown error while parsing referer data", :exception => e, :field => @source, :event => event)
    end

    if !referal_data.nil?
        event[@target] = {} if event[@target].nil?

        event[@target]["known"] = referal_data.known?
        event[@target]["name"] = referal_data.referer if not referal_data.referer.nil?
        event[@target]["host"] = referal_data.uri.host if not referal_data.uri.host.nil?

        # TODO: once the gem internal api is updated, more fields will be available
        if referal_data.known? and not referal_data.search_term.nil?
          event[@target]["search_term"] = referal_data.search_term
        end

      filter_matched(event)
    end

  end # def filter
end # class LogStash::Filters::Referal


