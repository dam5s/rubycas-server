require 'models'
require 'cas'
require 'localization'
require 'helpers'
require 'utils'

module CASServer
  class ServerConfig < Sinatra::Base
    include Models
    include CAS # CAS protocol helpers
    include Localization

    helpers do
      include Helpers
    end

    config = HashWithIndifferentAccess.new(
      :maximum_unused_login_ticket_lifetime   => 5.minutes,
      :maximum_unused_service_ticket_lifetime => 5.minutes, # CAS Protocol Spec, sec. 3.2.1 (recommended expiry time)
      :maximum_session_lifetime               => 1.month,   # All tickets are deleted after this period of time
      :log => {:file => 'casserver.log', :level => 'DEBUG'},
      :uri_path => '/'
    )

    set :app_file, __FILE__
    set :public, File.expand_path(File.dirname(__FILE__)+"/../../public")
    set :config, config
    set :config_file_loaded, false
    set :haml, :format => :html5

    # XML templates will be rendered without layout by default
    alias :old_haml :haml
    def haml(template, options = {})
      options = options.merge(:layout => false) if template.to_s.match(/\.xml$/)
      old_haml(template, options)
    end

    # Automatically add prefix to URI
    def self.uri(path = '')
      (config[:uri_path] || '/') + path.to_s
    end

    def uri(path = '')
      self.class.uri(path)
    end

    def self.run!(options={})
      set options

      handler      = detect_rack_handler
      handler_name = handler.name.gsub(/.*::/, '')

      set :url_prefix, '/cas/'
      
      puts "== RubyCAS-Server is starting up " +
        "on port #{config[:port] || port} for #{environment} with backup from #{handler_name}" unless handler_name =~/cgi/i
      handler.run self, handler_options do |server|
        [:INT, :TERM].each { |sig| trap(sig) { quit!(server, handler_name) } }
        set :running, true
      end
    rescue Errno::EADDRINUSE => e
      puts "== Something is already running on port #{port}!"
    end

    def self.quit!(server, handler_name)
      ## Use thins' hard #stop! if available, otherwise just #stop
      server.respond_to?(:stop!) ? server.stop! : server.stop
      puts "\n== RubyCAS-Server is shutting down" unless handler_name =~/cgi/i
    end

    def self.load_config_file(config_file)
      begin
        config_file = File.open(config_file)
      rescue Errno::ENOENT => e
        $stderr.puts
        $stderr.puts "!!! Config file #{config_file.inspect} does not exist!"
        $stderr.puts
        raise e
      rescue Errno::EACCES => e
        $stderr.puts
        $stderr.puts "!!! Config file #{config_file.inspect} is not readable (permission denied)!"
        $stderr.puts
        raise e
      rescue => e
        $stderr.puts
        $stderr.puts "!!! Config file #{config_file.inspect} could not be read!"
        $stderr.puts
        raise e
      end
      
      config.merge! HashWithIndifferentAccess.new(YAML.load(config_file))
      set :server, config[:server] || 'webrick'
      set :config_file_loaded, true
    end

    def self.handler_options
      handler_options = {
        :Host => bind || config[:bind_address],
        :Port => config[:port] || 443
      }

      handler_options.merge(handler_ssl_options).to_hash.symbolize_keys!
    end

    def self.handler_ssl_options
      return {} unless config[:ssl_cert]

      cert_path = config[:ssl_cert]
      key_path = config[:ssl_key] || config[:ssl_cert]
      
      unless cert_path.nil? && key_path.nil?
        raise Error, "The ssl_cert and ssl_key options cannot be used with mongrel. You will have to run your " +
          " server behind a reverse proxy if you want SSL under mongrel." if
            config[:server] == 'mongrel'

        raise Error, "The specified certificate file #{cert_path.inspect} does not exist or is not readable. " +
          " Your 'ssl_cert' configuration setting must be a path to a valid " +
          " ssl certificate." unless
            File.exists? cert_path

        raise Error, "The specified key file #{key_path.inspect} does not exist or is not readable. " +
          " Your 'ssl_key' configuration setting must be a path to a valid " +
          " ssl private key." unless
            File.exists? key_path

        require 'openssl'
        require 'webrick/https'

        cert = OpenSSL::X509::Certificate.new(File.read(cert_path))
        key = OpenSSL::PKey::RSA.new(File.read(key_path))

        {
          :SSLEnable        => true,
          :SSLVerifyClient  => ::OpenSSL::SSL::VERIFY_NONE,
          :SSLCertificate   => cert,
          :SSLPrivateKey    => key
        }
      end
    end

    def self.init_authenticators!
      auth = []

      unless config[:authenticator].instance_of?(Array)
        config[:authenticator] = [config[:authenticator]]
      end
      
      # Attempt to instantiate the authenticator
      config[:authenticator].each do |authenticator|
        begin
          auth << [ authenticator[:class].constantize, authenticator ]
        rescue NameError
          if authenticator[:source].present?
            # config.yml explicitly names source file
            require authenticator[:source]
          else
            # the authenticator class hasn't yet been loaded, so lets try to load it from the casserver/authenticators directory
            auth_rb = authenticator[:class].underscore.gsub('cas_server/', '')
            require 'casserver/'+auth_rb
          end

          auth << [ authenticator[:class].constantize, authenticator ]
        end
      end

      index = 0
      auth = auth.map do |class_and_config|
        index += 1
        klass, konfig = class_and_config

        $LOG.debug "About to setup #{klass} with #{konfig.inspect}..."
        instance = klass.new( konfig.merge('index' => index-1) )
        $LOG.debug "Done setting up #{klass}."
        instance
      end

      set :auth, auth
    end
    
    def self.init_database!
      Base.establish_connection(config[:database])
    end

    configure do
      begin
        config_file
      rescue NameError
        config_file = "/etc/rubycas-server/config.yml"
      end
      
      load_config_file(config_file) unless config_file_loaded?
      init_database!
      init_authenticators!
    end

    before do
      GetText.locale = determine_locale(request)
      @theme = 'urbacon'
      @organization = "URBACON"
    end

    def response_status_from_error(error)
      case error.code.to_s
      when /^INVALID_/, 'BAD_PGT'
        422
      when 'INTERNAL_ERROR'
        500
      else
        500
      end
    end

  end
end
