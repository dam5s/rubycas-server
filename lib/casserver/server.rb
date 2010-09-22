require 'config'

module CASServer
  class Server < ServerConfig
    get uri do
      redirect uri('login')
    end

    # The #.#.# comments (e.g. "2.1.3") refer to section numbers in the CAS protocol spec
    # under http://www.ja-sig.org/products/cas/overview/protocol/index.html

    # 2.1 :: Login

    # 2.1.1
    get uri('login') do
      Utils::log_action('GET /login', params)

      # make sure there's no caching
      headers['Pragma'] = 'no-cache'
      headers['Cache-Control'] = 'no-store'
      headers['Expires'] = (Time.now - 1.year).rfc2822

      # optional params
      @service = clean_service_url(params['service'])
      @renew = params['renew']
      @gateway = params['gateway'] == 'true' || params['gateway'] == '1'

      if tgc = request.cookies['tgt']
        tgt, tgt_error = validate_ticket_granting_ticket(tgc)
      end

      if tgt and !tgt_error
        @message = {
          :type => 'notice',
          :message => _("You are currently logged in as '%s'. If this is not you, please log in below.") % tgt.username
        }
      end

      if params['redirection_loop_intercepted']
        @message = {
          :type => 'mistake',
          :message => _("The client and server are unable to negotiate authentication. Please try logging in again later.")
        }
      end

      begin
        if @service
          if !@renew && tgt && !tgt_error
            st = generate_service_ticket(@service, tgt.username, tgt)
            service_with_ticket = service_uri_with_ticket(@service, st)
            $LOG.info("User '#{tgt.username}' authenticated based on ticket granting cookie. Redirecting to service '#{@service}'.")
            return redirect(service_with_ticket, :status => 303) # response code 303 means "See Other" (see Appendix B in CAS Protocol spec)
          elsif @gateway
            $LOG.info("Redirecting unauthenticated gateway request to service '#{@service}'.")
            return redirect(@service, :status => 303)
          end
        elsif @gateway
            $LOG.error("This is a gateway request but no service parameter was given!")
            @message = {:type => 'mistake',
              :message => _("The server cannot fulfill this gateway request because no service parameter was given.")}
        end
      rescue URI::InvalidURIError
        $LOG.error("The service '#{@service}' is not a valid URI!")
        @message = {:type => 'mistake',
          :message => _("The target service your browser supplied appears to be invalid. Please contact your system administrator for help.")}
      end

      lt = generate_login_ticket

      $LOG.debug("Rendering login form with lt: #{lt}, service: #{@service}, renew: #{@renew}, gateway: #{@gateway}")

      @lt = lt.ticket

      #$LOG.debug(env)

      # If the 'onlyLoginForm' parameter is specified, we will only return the
      # login form part of the page. This is useful for when you want to
      # embed the login form in some external page (as an IFRAME, or otherwise).
      # The optional 'submitToURI' parameter can be given to explicitly set the
      # action for the form, otherwise the server will try to guess this for you.
      if params.has_key? 'onlyLoginForm'
        if @env['HTTP_HOST']
          guessed_login_uri = "http#{@env['HTTPS'] && @env['HTTPS'] == 'on' ? 's' : ''}://#{@env['REQUEST_URI']}#{self / '/login'}"
        else
          guessed_login_uri = nil
        end

        @form_action = params['submitToURI'] || guessed_login_uri

        if @form_action
          haml :'login/form', :layout => false
        else
          @status = 500
          _("Could not guess the CAS login URI. Please supply a submitToURI parameter with your request.")
        end
      else
        haml :'login/page'
      end
    end # get /login

    # 2.2
    post uri('login') do
      Utils::log_action('POST /login', params)

      # 2.2.1 (optional)
      @service = clean_service_url(params['service'])

      # 2.2.2 (required)
      @username = params['username']
      @password = params['password']
      @lt = params['lt']

      # Remove leading and trailing widespace from username.
      @username.strip! if @username

      if @username && settings.config[:downcase_username]
        $LOG.debug("Converting username #{@username.inspect} to lowercase because 'downcase_username' option is enabled.")
        @username.downcase!
      end

      if error = validate_login_ticket(@lt)
        @message = {:type => 'mistake', :message => error}
        # generate another login ticket to allow for re-submitting the form
        @lt = generate_login_ticket.ticket
        @status = 401
        haml :'login/page'
      end

      # generate another login ticket to allow for re-submitting the form after a post
      @lt = generate_login_ticket.ticket

      $LOG.debug("Logging in with username: #{@username}, lt: #{@lt}, service: #{@service}, auth: #{settings.auth.inspect}")

      credentials_are_valid = false
      extra_attributes = {}
      successful_authenticator = nil

      begin
        settings.auth.each do |auth|
          credentials_are_valid = auth.validate(
            :username => @username,
            :password => @password,
            :service => @service,
            :request => @env
          )

          if credentials_are_valid
            extra_attributes.merge!(auth.extra_attributes) unless auth.extra_attributes.blank?
            successful_authenticator = auth
            break
          end
        end

      rescue AuthenticatorError => e
        $LOG.error(e)
        @message = {:type => 'mistake', :message => e.to_s}
        return render(:login)
      end

      if credentials_are_valid
        $LOG.info("Credentials for username '#{@username}' successfully validated using #{successful_authenticator.class.name}.")
        $LOG.debug("Authenticator provided additional user attributes: #{extra_attributes.inspect}") unless extra_attributes.blank?

        # 3.6 (ticket-granting cookie)
        tgt = generate_ticket_granting_ticket(@username, extra_attributes)

        if settings.config[:maximum_session_lifetime]
          expires     = settings.config[:maximum_session_lifetime].to_i.from_now
          expiry_info = " It will expire on #{expires}."

          request.cookies['tgt'] = {
            :value => tgt.to_s,
            :expires => expires
          }
        else
          expiry_info = " It will not expire."
          request.cookies['tgt'] = tgt.to_s
        end

        $LOG.debug("Ticket granting cookie '#{request.cookies['tgt'].inspect}' granted to #{@username.inspect}. #{expiry_info}")

        if @service.blank?
          $LOG.info("Successfully authenticated user '#{@username}' at '#{tgt.client_hostname}'. No service param was given, so we will not redirect.")
          @message = {:type => 'confirmation', :message => _("You have successfully logged in.")}
        else
          @st = generate_service_ticket(@service, @username, tgt)

          begin
            service_with_ticket = service_uri_with_ticket(@service, @st)

            $LOG.info("Redirecting authenticated user '#{@username}' at '#{@st.client_hostname}' to service '#{@service}'")
            redirect service_with_ticket, 303 # response code 303 means "See Other" (see Appendix B in CAS Protocol spec)
          rescue URI::InvalidURIError
            $LOG.error("The service '#{@service}' is not a valid URI!")
            @message = {
              :type => 'mistake',
              :message => _("The target service your browser supplied appears to be invalid. Please contact your system administrator for help.")
            }
          end
        end
      else
        $LOG.warn("Invalid credentials given for user '#{@username}'")
        @message = {:type => 'mistake', :message => _("Incorrect username or password.")}
        @status = 401
      end

      haml :'login/page'
    end # post /login

    # 2.3

    # 2.3.1
    get uri('logout') do
      Utils::log_action('GET /proxyValidate', params)

      # The behaviour here is somewhat non-standard. Rather than showing just a blank
      # "logout" page, we take the user back to the login page with a "you have been logged out"
      # message, allowing for an opportunity to immediately log back in. This makes it
      # easier for the user to log out and log in as someone else.
      @service = clean_service_url(params['service'] || params['destination'])
      @continue_url = params['url']

      @gateway = params['gateway'] == 'true' || params['gateway'] == '1'

      tgt = TicketGrantingTicket.find_by_ticket(request.cookies['tgt'])

      request.cookies.delete 'tgt'

      if tgt
        TicketGrantingTicket.transaction do
          $LOG.debug("Deleting Service/Proxy Tickets for '#{tgt}' for user '#{tgt.username}'")
          tgt.granted_service_tickets.each do |st|
            send_logout_notification_for_service_ticket(st) if $CONF.enable_single_sign_out
            # TODO: Maybe we should do some special handling if send_logout_notification_for_service_ticket fails?
            #       (the above method returns false if the POST results in a non-200 HTTP response).
            $LOG.debug "Deleting #{st.class.name.demodulize} #{st.ticket.inspect} for service #{st.service}."
            st.destroy
          end

          pgts = ProxyGrantingTicket.find(:all,
            :conditions => [Base.connection.quote_table_name(ServiceTicket.table_name)+".username = ?", tgt.username],
            :include => :service_ticket)
          pgts.each do |pgt|
            $LOG.debug("Deleting Proxy-Granting Ticket '#{pgt}' for user '#{pgt.service_ticket.username}'")
            pgt.destroy
          end

          $LOG.debug("Deleting #{tgt.class.name.demodulize} '#{tgt}' for user '#{tgt.username}'")
          tgt.destroy
        end

        $LOG.info("User '#{tgt.username}' logged out.")
      else
        $LOG.warn("User tried to log out without a valid ticket-granting ticket.")
      end

      @message = {:type => 'confirmation', :message => _("You have successfully logged out.")}

      @message[:message] +=_(" Please click on the following link to continue:") if @continue_url

      @lt = generate_login_ticket

      if @gateway && @service
        redirect @service, 303
      elsif @continue_url
        haml :logout
      else
        haml :'login/page'
      end
    end # get /logout

    # 2.6 :: ProxyValidate

    # 2.6.1
    get uri('proxyValidate') do
      Utils::log_action('GET /proxyValidate', params)

      @service = clean_service_url(params['service'])
      @ticket  = params['ticket']
      @pgt_url = params['pgtUrl']
      @renew   = params['renew']

      @proxies = []

      ticket, @error = validate_proxy_ticket(@service, @ticket)
      @success = ticket && !@error

      @extra_attributes = {}
      if @success
        @username = ticket.username

        if ticket.kind_of?(ProxyTicket)
          @proxies << ticket.granted_by_pgt.service_ticket.service
        end

        if @pgt_url
          pgt = generate_proxy_granting_ticket(@pgt_url, ticket)
          @pgtiou = pgt.iou if pgt
        end

        @extra_attributes = ticket.granted_by_tgt.extra_attributes || {}
      end

      @status = response_status_from_error(@error) if @error

      haml "proxy_validate/#{@success ? 'success' : 'failure'}.xml".to_sym
    end # get /proxyValidate
  end
end
