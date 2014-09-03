require "logstash/filters/base"
require "logstash/namespace"

# Parse referer strings into structured data based on snowplow data
# 
# Referer filter, adds information about referer source, provider, etc 
#
# Logstash releases ship with the referers.yaml database made available from
# referer-parser with an Apache 2.0 license. For more details on referer-parser, see
# <https://github.com/snowplow/referer-parser>.
class LogStash::Filters::Referal < LogStash::Filters::Base
  config_name "referal"
  milestone 1

  # The field containing the referer string. If this field is an
  # array, only the first value will be used.
  config :source, :validate => :string, :required => true

  # The name of the field to assign referer data into.
  #
  # If not specified referer data will be stored in the root of the event.
  config :target, :validate => :string

  # referers.yaml file to use
  #
  # If not specified, this will default to the referers.yaml that ships
  # with referer-parser.
  #
  # You can find the latest version of this here:
  # <https://github.com/snowplow/referer-parser/blob/master/resources/referers.yml>
  config :referers_file, :validate => :string

  # custom-referers.yaml file to use for internal domains
  #
  # If not specified, no other referers will be merged into the parser.
  config :custom_referers_file, :validate => :string

  # A string to prepend to all of the extracted keys
  config :prefix, :validate => :string, :default => ''

  public

  def register
    require 'referer-parser'

    if @referers.nil?
      @logger.info("Using default referer file: #{RefererParser::Parser::DefaultFile}")
      @parser = RefererParser::Parser.new
    else
      referer_files = [@referers_file, @custom_referers_file].compact
      @logger.info("Using custom referer file(s): #{referer_files.join(', ')}")
      @parser = RefererParser::Parser.new(referer_files)
    end
  end #def register

  def filter(event)
    return unless filter?(event)
    referer_data = nil

    referer = event[@source]
    referer = referer.first if referer.is_a? Array

    begin
      referer_data = @parser.parse(referer) unless referer.nil? or referer.strip == ''
    rescue Exception => e
      @logger.error("Uknown error while parsing referer data", :exception => e, :field => @source, :event => event)
    end

    if !referer_data.nil?
      if @target.nil?
        # default write to the root of the event
        target = event
      else
        target = event[@target] ||= {}
      end

      # To match historical naming conventions
      target[@prefix + "known"] = referer_data[:known]
      target[@prefix + "name"] = referer_data[:source] if referer_data.has_key?(:source)
      target[@prefix + "medium"] = referer_data[:medium] if referer_data.has_key?(:medium)
      target[@prefix + "search_term"] = referer_data[:term] if referer_data.has_key?(:term)
      target[@prefix + "host"] = referer_data[:domain] if referer_data.has_key?(:domain)

      filter_matched(event)
    end
  end # def filter
end # class LogStash::Filters::Referal
