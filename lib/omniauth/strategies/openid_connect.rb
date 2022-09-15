# frozen_string_literal: true

require 'addressable/uri'
require 'timeout'
require 'net/http'
require 'open-uri'
require 'omniauth'
require 'openid_connect'
require 'forwardable'

module OmniAuth
  module Strategies
    class OpenIDConnect
      include OmniAuth::Strategy
      extend Forwardable

      RESPONSE_TYPE_EXCEPTIONS = {
          'id_token' => { exception_class: OmniAuth::OpenIDConnect::MissingIdTokenError, key: :missing_id_token }.freeze,
          'code' => { exception_class: OmniAuth::OpenIDConnect::MissingCodeError, key: :missing_code }.freeze,
      }.freeze

      def_delegator :request, :params

      option :name, 'openid_connect'
      option(:client_options, identifier: nil,
             secret: nil,
             redirect_uri: nil,
             scheme: 'https',
             host: nil,
             port: 443,
             authorization_endpoint: '/authorize',
             token_endpoint: '/token',
             userinfo_endpoint: '/userinfo',
             jwks_uri: '/jwk',
             verify_uri: '/introspect',
             end_session_endpoint: nil)

      option :issuer
      option :discovery, false
      option :client_signing_alg
      option :client_jwk_signing_key
      option :client_x509_signing_key
      option :scope, [:openid]
      option :response_type, 'code' # ['code', 'id_token']
      option :state
      option :response_mode # [:query, :fragment, :form_post, :web_message]
      option :display, nil # [:page, :popup, :touch, :wap]
      option :prompt, nil # [:none, :login, :consent, :select_account]
      option :hd, nil
      option :max_age
      option :ui_locales
      option :id_token_hint
      option :acr_values
      option :send_nonce, true
      option :send_scope_to_token_endpoint, true
      option :client_auth_method
      option :post_logout_redirect_uri
      option :extra_authorize_params, {}
      option :uid_field, 'sub'

      def uid
        #puts "in uid"
        user_info.raw_attributes[options.uid_field.to_sym] || user_info.sub
        #options.uid_field.to_sym || user_info.sub
      end

      info do
        #puts "ininfo:#{user_info.name}"
        {
            name: user_info.name,
            email: user_info.email,
            nickname: user_info.preferred_username,
            first_name: user_info.given_name,
            last_name: user_info.family_name,
            gender: user_info.gender,
            image: user_info.picture,
            phone: user_info.phone_number,
            provider: options.name,
            uid: user_info.sub,
            urls: { website: user_info.website },

        }
      end

      extra do
        { raw_info: user_info.raw_attributes }
      end

      credentials do
        {
            id_token: @id_token,
            token:  @token,
            refresh_token: @refresh_token,
            expires_in: @expires_in,
            scope: @scope,
        }
      end


      def client
        @client ||= ::OpenIDConnect::Client.new(client_options)
      end

      def config
        @config ||= ::OpenIDConnect::Discovery::Provider::Config.discover!(options.issuer)
      end

      def request_phase
        options.issuer = issuer if options.issuer.to_s.empty?
        discover!
        redirect authorize_uri
      end

      def callback_phase
        #puts "In callback_phase"
        error = params['error_reason'] || params['error']
        error_description = params['error_description'] || params['error_reason']
        invalid_state = params['state'].to_s.empty? || params['state'] != stored_state
        #puts "invalid_state:#{invalid_state}"
        raise CallbackError, error: params['error'], reason: error_description, uri: params['error_uri'] if error
        raise CallbackError, error: :csrf_detected, reason: "Invalid 'state' parameter" if invalid_state
        #puts "valid_response_type?:#{valid_response_type?}"
        return unless valid_response_type?

        options.issuer = issuer if options.issuer.nil? || options.issuer.empty?
        #puts "options.issuer:#{options.issuer}"
        verify_id_token!(params['id_token']) if configured_response_type == 'id_token'
        discover!
        client.redirect_uri = redirect_uri

        return id_token_callback_phase if configured_response_type == 'id_token'
        #puts "authorization_code:#{authorization_code}"
        client.authorization_code = authorization_code
        #puts "access_token:#{access_token}"
        access_token
        super
      rescue CallbackError => e
        fail!(e.error, e)
      rescue ::Rack::OAuth2::Client::Error => e
        fail!(e.response[:error], e)
      rescue ::Timeout::Error, ::Errno::ETIMEDOUT => e
        fail!(:timeout, e)
      rescue ::SocketError => e
        fail!(:failed_to_connect, e)
      end



      def other_phase
        # puts "In other_phase"
        if logout_path_pattern.match?(current_path)
          options.issuer = issuer if options.issuer.to_s.empty?
          discover!
          return redirect(end_session_uri) if end_session_uri
        end
        call_app!
      end

      def authorization_code
        params['code']
      end

      def end_session_uri
        return unless end_session_endpoint_is_valid?

        end_session_uri = URI(client_options.end_session_endpoint)
        end_session_uri.query = encoded_post_logout_redirect_uri
        end_session_uri.to_s
      end

      def authorize_uri
        #puts "In authorize_uri"
        client.redirect_uri = redirect_uri
        opts = {
            response_type: options.response_type,
            response_mode: options.response_mode,
            scope: options.scope,
            state: new_state,
            login_hint: params['login_hint'],
            ui_locales: params['ui_locales'],
            claims_locales: params['claims_locales'],
            prompt: options.prompt,
            nonce: (new_nonce if options.send_nonce),
            hd: options.hd,
            acr_values: options.acr_values,
        }

        opts.merge!(options.extra_authorize_params) unless options.extra_authorize_params.empty?

        client.authorization_uri(opts.reject { |_k, v| v.nil? })
      end

      def public_key
        return config.jwks if options.discovery

        key_or_secret
      end

      private

      def issuer
        resource = "#{ client_options.scheme }://#{ client_options.host }"
        resource = "#{ resource }:#{ client_options.port }" if client_options.port
        ::OpenIDConnect::Discovery::Provider.discover!(resource).issuer
      end

      def discover!
        return unless options.discovery
        #puts "config:#{config.to_s}"
        client_options.authorization_endpoint = config.authorization_endpoint
        client_options.token_endpoint = config.token_endpoint
        client_options.userinfo_endpoint = config.userinfo_endpoint
        client_options.jwks_uri = config.jwks_uri
        client_options.end_session_endpoint = config.end_session_endpoint if config.respond_to?(:end_session_endpoint)
      end

      def user_info
        return @user_info if @user_info
        token_hash = JSON.parse(access_token).with_indifferent_access
        id_token=token_hash[:id_token]
        access_token=token_hash[:access_token]
        # if access_token.id_token
        #   decoded = decode_id_token(access_token.id_token).raw_attributes
        #
        #   @user_info = ::OpenIDConnect::ResponseObject::UserInfo.new access_token.userinfo!.raw_attributes.merge(decoded)
        # else
        #   @user_info = access_token.userinfo!
        # end
        verify_status=verify_token!(id_token,'id_token')
        if(verify_status[:active])
          user=get_user_info(access_token)
          #puts "user:#{user}"
          @user_info = ::OpenIDConnect::ResponseObject::UserInfo.new user.merge(verify_status)
        else
          raise InvalidToken.new('Invalid ID token')
        end
        # @user_info =::OpenIDConnect::ResponseObject::UserInfo.new({
        #     "iss": "https://auth.pingone.asia/2b8c6599-7834-4d4b-9cf6-96c3c8ebb106/as",
        #     "sub": "b34c8bd1-f9df-4804-a3c5-91ba6f592bac",
        #     "aud": "a3bfb78c-a841-4e4c-a2aa-d66071b28500",
        #     "iat": 1662869285,
        #     "exp": 1662872885,
        #     "acr": "Multi_Factor",
        #     "amr": [
        #         "mfa",
        #         "mca",
        #         "user"
        #     ],
        #     "auth_time": 1662869282,
        #     "at_hash": "5DtR1S9iPFgdOtBGIm_ZMg",
        #     "nonce": "29321497f38d29a961676ecc0fecb386",
        #     "sid": "83bab3e2-0238-4c28-8e10-0a441ac88d1f",
        #     "email": "sayalihole.hole1@gmail.com",
        #     "preferred_username": "sayali_2002",
        #     "given_name": "sayali",
        #     "middle_name": "vinayak",
        #     "name": "sayali hole",
        #     "updated_at": 1662869282,
        #     "family_name": "hole",
        #     "nickname": "sayali",
        #     "FirstName": "sayali",
        #     "LastName": "hole",
        #     "EmailAddress": "sayalihole.hole1@gmail.com",
        #     "env": "2b8c6599-7834-4d4b-9cf6-96c3c8ebb106",
        #     "org": "fe9b380a-aca2-4429-9053-46977ec84420",
        #     "p1.region": "AP"
        # })
      end

      def access_token
        #puts "In access token"
        return @access_token if @access_token

        @access_token = access_token_check(
            scope: (options.scope if options.send_scope_to_token_endpoint),
            client_auth_method: options.client_auth_method
        )
        #puts "access token1:#{@access_token}"
        #Rack ::OAuth2::AccessToken.new(data)
        #verify_id_token!(@access_token.id_token) if configured_response_type == 'code'
        #puts "access token2:#{@access_token}"
        #@access_token
        @access_token
      end

      def access_token_check(*args)
        headers,params, http_client, options = authenticated_context_from(*args)
        headers1= {}
        headers1.merge!(
            'Content-Type' => "application/x-www-form-urlencoded",
            'Host'=> client_options.host
        )
        params[:scope] = Array(options.delete(:scope)).join(' ') if options[:scope].present?
        params[:client_id]=client_options.identifier
        params[:client_secret]=client_options.secret
        params[:code]=authorization_code
        params[:grant_type]="authorization_code"
        params[:redirect_uri]=client_options.redirect_uri
        #@grant = Grant::ClientCredentials.new
        #puts "grant:#{@grant.as_json}"
        #params.merge! @grant.as_json
        params.merge! options
        #puts "params:#{::Rack::OAuth2::Util.compact_hash(params)}"
        c=::Rack::OAuth2::Util.compact_hash(params)
        #puts "code:#{c[:code]}"
        #puts "RootCA:#{Rails.root}"
        uri = URI.parse(client_options.token_endpoint)
        uri.query = URI.encode_www_form( ::Rack::OAuth2::Util.compact_hash(params) )
        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = true
        http.verify_mode = OpenSSL::SSL::VERIFY_NONE

        request = Net::HTTP::Post.new(uri, headers1)
        #puts "uri:#{uri}"
        #puts "headers:#{headers1}"
        response = http.request(request)

        #puts response.body
        #puts response.code
        handle_response(response)
        return response.body
      end

      def verify_token!(id_token,token_type)
        return unless id_token
        token_verfiy_endpoint=client_options.verify_uri
        params= {}
        headers1= {}
        headers1.merge!(
            'Content-Type' => "application/x-www-form-urlencoded",
            'Host'=> client_options.host
        )
        params[:token] = id_token
        params[:token_type_hint]=token_type
        params[:client_id]=client_options.identifier
        params[:client_secret]=client_options.secret
        #puts "params:#{::Rack::OAuth2::Util.compact_hash(params)}"
        c=::Rack::OAuth2::Util.compact_hash(params)
        #puts "code:#{c[:code]}"

        #puts "RootCA:#{Rails.root}"
        uri = URI.parse(token_verfiy_endpoint)
        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = true
        http.verify_mode = OpenSSL::SSL::VERIFY_NONE

        request = Net::HTTP::Post.new(uri, headers1)
        #puts "uri:#{uri}"
        #puts "headers:#{headers1}"
        #puts "body:#{request.body}"
        post_data = URI.encode_www_form(params)
        response = http.request(request,post_data)
        return handle_user_response(response)
      end

      def get_user_info(token)
        return unless token
        token_verfiy_endpoint=client_options.userinfo_endpoint
        params= {}
        headers1= {}
        headers1.merge!(
            'Content-Type' => "application/x-www-form-urlencoded",
            'Host'=> client_options.host,
            'Authorization'=> "Bearer "+token
        )
        uri = URI.parse(token_verfiy_endpoint)
        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = true
        http.verify_mode = OpenSSL::SSL::VERIFY_NONE

        request = Net::HTTP::Post.new(uri, headers1)
        #puts "uri:#{uri}"
        #puts "headers:#{headers1}"
        response = http.request(request)
        get_info
        return handle_user_response(response)
      end
      def get_info
        token_hash = JSON.parse(access_token).with_indifferent_access
        @id_token= token_hash[:id_token]
        @token= token_hash[:access_token],
            @refresh_token= token_hash[:refresh_token],
            @expires_in= token_hash[:expires_in],
            @scope= token_hash[:scope]
      end

      def handle_user_response(res)
        case res.code.to_i
        when 200
          JSON.parse(res.body).with_indifferent_access
        when 400
          raise BadRequest.new('API Access Faild', res)
        when 401
          raise Unauthorized.new('Access Token Invalid or Expired', res)
        when 403
          raise Forbidden.new('Insufficient Scope', res)
        else
          raise HttpError.new(res.status, 'Unknown HttpError', res)
        end
      end

      def authenticated_context_from(*args)
        headers, params = {}, {}
        http_client = Rack::OAuth2.http_client

        # NOTE:
        #  Using Array#extract_options! for backward compatibility.
        #  Until v1.0.5, the first argument was 'client_auth_method' in scalar.
        options = args.extract_options!
        client_auth_method = args.first || options.delete(:client_auth_method).try(:to_sym) || :basic

        case client_auth_method
        when :basic
          cred = Base64.strict_encode64 [
                                            ::Rack::OAuth2::Util.www_form_url_encode(client_options.identifier),
                                            ::Rack::OAuth2::Util.www_form_url_encode(client_options.secret)
                                        ].join(':')
          headers.merge!(
              'Authorization' => "Basic #{cred}"
          )
        when :basic_without_www_form_urlencode
          cred = ["#{client_options.identifier}:#{client_options.secret}"].pack('m').tr("\n", '')
          headers.merge!(
              'Authorization' => "Basic #{cred}"
          )
        when :jwt_bearer
          params.merge!(
              client_assertion_type: URN::ClientAssertionType::JWT_BEARER
          )
          # NOTE: optionally auto-generate client_assertion.
          params[:client_assertion] = if options[:client_assertion].present?
                                        options.delete(:client_assertion)
                                      else
                                        require 'json/jwt'
                                        JSON::JWT.new(
                                            iss: identifier,
                                            sub: identifier,
                                            aud: absolute_uri_for(client_options.token_endpoint),
                                            jti: SecureRandom.hex(16),
                                            iat: Time.now,
                                            exp: 3.minutes.from_now
                                        ).sign(private_key || secret).to_s
                                      end
        when :saml2_bearer
          params.merge!(
              client_assertion_type: URN::ClientAssertionType::SAML2_BEARER
          )
        when :mtls
          params.merge!(
              client_id: identifier
          )
          http_client.ssl_config.client_key = private_key
          http_client.ssl_config.client_cert = certificate
        else
          params.merge!(
              client_id: client_options.identifier,
              client_secret: client_options.secret
          )
        end

        [headers, params, http_client, options]
      end

      def handle_response(response)
        #response = yield
        puts "status:#{response.code.to_i}"
        case response.code.to_i
        when 200
          puts "in success 200"
          handle_success_response(response)
        else
          puts "in error"
          handle_error_response(response)
        end
      end

      def handle_revocation_response
        response = yield
        case response.status
        when 200..201
          :success
        else
          handle_error_response response
        end
      end

      def handle_success_response(response)
        #puts "In handle_success_response"
        token_hash = JSON.parse(response.body).with_indifferent_access
        #puts "In handle_success_response:#{token_hash[:token_type]}"
        case (@forced_token_type || token_hash[:token_type]).try(:downcase)
        when 'bearer'
          ::Rack::OAuth2::AccessToken::Bearer.new(token_hash)
        when 'mac'
          ::Rack::OAuth2::AccessToken::MAC.new(token_hash)
        when nil
          ::Rack::OAuth2::AccessToken::Legacy.new(token_hash)
        else
          raise 'Unknown Token Type'
        end
      rescue JSON::ParserError
        # NOTE: Facebook support (They don't use JSON as token response)
        AccessToken::Legacy.new Rack::Utils.parse_nested_query(response.body).with_indifferent_access
      end

      def handle_error_response(response)
        error = JSON.parse(response.body).with_indifferent_access
        raise Error.new(response.code, error)
      rescue JSON::ParserError
        raise Error.new(response.code, error: 'Unknown', error_description: response.body)
      end

      def decode_id_token(id_token)
        ::OpenIDConnect::ResponseObject::IdToken.decode(id_token, public_key)
      end

      def client_options
        options.client_options
      end

      def new_state
        # state = if options.state.respond_to?(:call)
        #           if options.state.arity == 1
        #             options.state.call(env)
        #           else
        #             options.state.call
        #           end
        #         end
        #puts "state:#{options.state}"
        state=options.state
        session['omniauth.state'] = state || SecureRandom.hex(16)
      end

      def stored_state
        session.delete('omniauth.state')
      end

      def new_nonce
        session['omniauth.nonce'] = SecureRandom.hex(16)
      end

      def stored_nonce
        session.delete('omniauth.nonce')
      end

      def session
        return {} if @env.nil?

        super
      end

      def key_or_secret
        #puts "key_or_secret:#{options.client_signing_alg}"
        case options.client_signing_alg
        when :HS256, :HS384, :HS512
          client_options.secret
        when :RS256, :RS384, :RS512
          puts "client_jwk_signing_key:#{options.client_jwk_signing_key}"
          if options.client_jwk_signing_key
            parse_jwk_key(res)
          elsif options.client_x509_signing_key
            parse_x509_key(options.client_x509_signing_key)
          end
        end
      end

      def parse_x509_key(key)
        OpenSSL::X509::Certificate.new(key).public_key
      end

      def parse_jwk_key(key)
        key='{
                "keys": [
                    {
                        "kty": "RSA",
                        "kid": "default",
                        "use": "sig",
                        "n": "jgQ8twHSmSlT28I7iTi4-IsA3jgfhGPx0pIC27LTDf0q4wBE8Ap5dG7kqL9GE7zoxleghUs6APQ0qKWaTxBSqxISzZmZpRQqipM-Tog3wgLciIbRozRHTXmCmzFJcG5spoe2XtcZ3zMRs9kkOUzxN2XMXHBidQKFB82_NjDwqhW_gdbS1vJLt1j9gjl60wvXcTwFzTkqh6owGjMCVFrraEv-H6XdhP4VMM7gsPOSD-IJke0CmQyVMVXVWoydahMLqLuz59HBUCYFcW0HVJLDMKJvNoFhY9xZW3oiVrNPP7COdv5-4SLq3EIi5WVd9TglYDQt2SmyDV36pcBPautKvQ",
                        "e": "AQAB",
                        "x5c": [
                            "MIIDLDCCAhSgAwIBAgIGAWW17v5GMA0GCSqGSIb3DQEBCwUAMFcxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRUwEwYDVQQKEwxQaW5nSWRlbnRpdHkxEzARBgNVBAMTCnByb2Qtb2F1dGgwHhcNMTgwOTA3MjEyNzQzWhcNMjMwOTA2MjEyNzQzWjBXMQswCQYDVQQGEwJVUzELMAkGA1UECBMCQ08xDzANBgNVBAcTBkRlbnZlcjEVMBMGA1UEChMMUGluZ0lkZW50aXR5MRMwEQYDVQQDEwpwcm9kLW9hdXRoMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAjgQ8twHSmSlT28I7iTi4+IsA3jgfhGPx0pIC27LTDf0q4wBE8Ap5dG7kqL9GE7zoxleghUs6APQ0qKWaTxBSqxISzZmZpRQqipM+Tog3wgLciIbRozRHTXmCmzFJcG5spoe2XtcZ3zMRs9kkOUzxN2XMXHBidQKFB82/NjDwqhW/gdbS1vJLt1j9gjl60wvXcTwFzTkqh6owGjMCVFrraEv+H6XdhP4VMM7gsPOSD+IJke0CmQyVMVXVWoydahMLqLuz59HBUCYFcW0HVJLDMKJvNoFhY9xZW3oiVrNPP7COdv5+4SLq3EIi5WVd9TglYDQt2SmyDV36pcBPautKvQIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQB42oNEjRUNRbMEnrQ6UyyyVu+DW6lL19RJoCasb4hRWe/YHr11xF3+JMObsaaRBA0/jJ7SAFiJxNpBC48ceXDK+mS3VbGDBj+Isi19Csa1HO0VpERKuNuaXmUGmJm4hkMcYFbnjC9+g/3bzDDiZWAiZUrqVA6HEj4MXb5/m7492msSFnhZ06qjAVj/qpRcVBIAIy1XCvTB2X913x4r+CjrWd0x3nHcjr2qfnmw96qPQU82MagWXenNNZbLpy+rDbWjYDB/bW3Rgp4704PLixar5gGR69x3JCvfr7N45oOYTQcZmTasF7W5Ee2bsR2NXu1KvI7fLgLifz25V/eqYtjY"
                        ],
                        "x5t": "Za6ddv8nZnWoqvY6z61fiP8QwEo"
                    }
                ]
            }'
        json = JSON.parse(key)
        return JSON::JWK::Set.new(json['keys']) if json.key?('keys')

        JSON::JWK.new(json)
      end

      def decode(str)
        UrlSafeBase64.decode64(str).unpack1('B*').to_i(2).to_s
      end

      def redirect_uri
        #puts "redirect_uri"
        return client_options.redirect_uri unless params['redirect_uri']

        "#{ client_options.redirect_uri }?redirect_uri=#{ CGI.escape(params['redirect_uri']) }"
      end

      def encoded_post_logout_redirect_uri
        #puts "encoded_post_logout_redirect_uri"
        return unless options.post_logout_redirect_uri

        URI.encode_www_form(
            post_logout_redirect_uri: options.post_logout_redirect_uri
        )
      end

      def end_session_endpoint_is_valid?
        #puts "end_session_endpoint_is_valid?"
        client_options.end_session_endpoint &&
            client_options.end_session_endpoint =~ URI::DEFAULT_PARSER.make_regexp
      end

      def logout_path_pattern
        @logout_path_pattern ||= %r{\A#{Regexp.quote(request_path)}(/logout)}
      end

      def id_token_callback_phase
        #puts "id_token_callback_phase"
        # user_data = decode_id_token(params['id_token']).raw_attributes
        #puts "user_data['name']:#{user_info.name}"
        env['omniauth.auth'] = AuthHash.new(
            provider: name,
            uid: user_info.sub,
            info: { name: user_info.name, email: user_info.email },
            extra: { raw_info: user_info }
        )
        #puts " env['omniauth.auth']:#{ env['omniauth.auth']}"
        call_app!
      end

      def valid_response_type?
        return true if params.key?(configured_response_type)

        error_attrs = RESPONSE_TYPE_EXCEPTIONS[configured_response_type]
        fail!(error_attrs[:key], error_attrs[:exception_class].new(params['error']))

        false
      end

      def configured_response_type
        @configured_response_type ||= options.response_type.to_s
      end

      def verify_id_token!(id_token)
        return unless id_token

        decode_id_token(id_token).verify!(issuer: options.issuer,
                                          client_id: client_options.identifier,
                                          nonce: stored_nonce)
      end

      class CallbackError < StandardError
        attr_accessor :error, :error_reason, :error_uri

        def initialize(data)
          self.error = data[:error]
          self.error_reason = data[:reason]
          self.error_uri = data[:uri]
        end

        def message
          [error, error_reason, error_uri].compact.join(' | ')
        end
      end
    end
  end
end

OmniAuth.config.add_camelization 'openid_connect', 'OpenIDConnect'
