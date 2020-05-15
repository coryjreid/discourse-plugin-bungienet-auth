# frozen_string_literal: true

# name: discourse-plugin-bungienet-auth
# about: An OAuth 2.0 authentication plugin for Bungie.net
# version: 0.0.1
# authors: Cory Reid
# url: https://github.com/coryjreid/discourse-plugin-bungienet-auth

require_dependency 'auth/oauth2_authenticator.rb'

enabled_site_setting :bungienet_enabled

class ::OmniAuth::Strategies::Bungienet < ::OmniAuth::Strategies::OAuth2
  option :name, "bungienet"

  uid do
    if path = SiteSetting.bungienet_callback_user_id_path.split('.')
      recurse(access_token, [*path]) if path.present?
    end
  end

  # When developing locally this will need to be modified to match an HTTPS
  # tunnel provided by ngrok or it will be impossible to authenticate with
  # Bungie.net (silent failures, yay!).
  #
  # Example: 'https://haslkdfjha.ngrok.io' + script_name + callback_path
  def callback_url
    Discourse.base_url_no_prefix + script_name + callback_path
  end

  def recurse(obj, keys)
    return nil if !obj
    k = keys.shift
    result = obj.respond_to?(k) ? obj.send(k) : obj[k]
    keys.empty? ? result : recurse(result, keys)
  end
end

if Gem::Version.new(Faraday::VERSION) > Gem::Version.new('1.0')
  require 'faraday/logging/formatter'

  class OAuth2FaradayFormatter < Faraday::Logging::Formatter
    def request(env)
      warn <<~LOG
        Bungie.net Auth Debugging: request #{env.method.upcase} #{env.url.to_s}

        Headers: #{env.request_headers}

        Body: #{env[:body]}
      LOG
    end

    def response(env)
      warn <<~LOG
        Bungie.net Auth Debugging: response status #{env.status}

        From #{env.method.upcase} #{env.url.to_s}

        Headers: #{env.response_headers}

        Body: #{env[:body]}
      LOG
    end
  end
end

class ::BungienetAuthenticator < Auth::ManagedAuthenticator
  def name
    'bungienet'
  end

  def can_revoke?
    SiteSetting.bungienet_allow_association_change
  end

  def can_connect_existing_user?
    SiteSetting.bungienet_allow_association_change
  end

  def register_middleware(omniauth)
    omniauth.provider :bungienet,
                      name: name,
                      setup: lambda { |env|
                        opts = env['omniauth.strategy'].options
                        opts[:client_id] = SiteSetting.bungienet_client_id
                        opts[:client_secret] = SiteSetting.bungienet_client_secret
                        opts[:provider_ignores_state] = false
                        opts[:client_options] = {
                            authorize_url: SiteSetting.bungienet_authorize_url,
                            token_url: SiteSetting.bungienet_token_url,
                            token_method: SiteSetting.bungienet_token_url_method.downcase.to_sym
                        }
                        opts[:client_options][:auth_scheme] = :request_body

                        if SiteSetting.bungienet_debug_auth && defined? OAuth2FaradayFormatter
                          opts[:client_options][:connection_build] = lambda { |builder|
                            builder.response :logger, Rails.logger, {bodies: true, formatter: OAuth2FaradayFormatter}

                            # Default stack:
                            builder.request :url_encoded # form-encode POST params
                            builder.adapter Faraday.default_adapter # make requests with Net::HTTP
                          }
                        end
                      }
  end

  def walk_path(fragment, segments, seg_index = 0)
    first_seg = segments[seg_index]
    return if first_seg.blank? || fragment.blank?
    return nil unless fragment.is_a?(Hash) || fragment.is_a?(Array)
    first_seg = segments[seg_index].scan(/([\d+])/).length > 0 ? first_seg.split("[")[0] : first_seg
    if fragment.is_a?(Hash)
      deref = fragment[first_seg] || fragment[first_seg.to_sym]
    else
      array_index = 0
      if (seg_index > 0)
        last_index = segments[seg_index - 1].scan(/([\d+])/).flatten() || [0]
        array_index = last_index.length > 0 ? last_index[0].to_i : 0
      end
      if fragment.any? && fragment.length >= array_index - 1
        deref = fragment[array_index][first_seg]
      else
        deref = nil
      end
    end

    if (deref.blank? || seg_index == segments.size - 1)
      deref
    else
      seg_index += 1
      walk_path(deref, segments, seg_index)
    end
  end

  def json_walk(result, user_json, prop)
    path = SiteSetting.public_send("bungienet_json_#{prop}_path")
    if path.present?
      #this.[].that is the same as this.that, allows for both this[0].that and this.[0].that path styles
      path = path.gsub(".[].", ".").gsub(".[", "[")
      segments = path.split('.')
      val = walk_path(user_json, segments)
      result[prop] = val if val.present?
    end
  end

  def log(info)
    Rails.logger.warn("Bungie.net Auth Debugging: #{info}") if SiteSetting.bungienet_debug_auth
  end

  def fetch_user_details(token, id)
    user_json_url = SiteSetting.bungienet_user_json_url.sub(':token', token.to_s).sub(':id', id.to_s)
    user_json_method = SiteSetting.bungienet_user_json_url_method

    log("user_json_url: #{user_json_method} #{user_json_url}")

    bearer_token = "Bearer #{token}"
    connection = Excon.new(
        user_json_url,
        headers: {
            'Authorization' => bearer_token,
            'Accept' => 'application/json',
            'X-API-Key' => SiteSetting.bungienet_api_key
        }
    )
    user_json_response = connection.request(method: user_json_method)

    log("user_json_response: #{user_json_response.inspect}")

    if user_json_response.status == 200
      user_json = JSON.parse(user_json_response.body)

      log("user_json: #{user_json}")

      result = {}
      if user_json.present?
        json_walk(result, user_json, :user_id)
        json_walk(result, user_json, :username)
        json_walk(result, user_json, :name)
        json_walk(result, user_json, :avatar)
      end
      result
    else
      nil
    end
  end

  def after_authenticate(auth, existing_account: nil)
    log("after_authenticate response: \n\ncreds: #{auth['credentials'].to_hash}\nuid: #{auth['uid']}\ninfo: #{auth['info'].to_hash}\nextra: #{auth['extra'].to_hash}")

    if fetched_user_details = fetch_user_details(auth['credentials']['token'], auth['uid'])
      auth['uid'] = fetched_user_details[:user_id] if fetched_user_details[:user_id]
      auth['info']['nickname'] = fetched_user_details[:username] if fetched_user_details[:username]
      auth['info']['image'] = fetched_user_details[:avatar] if fetched_user_details[:avatar]
    else
      result = Auth::Result.new
      result.failed = true
      result.failed_reason = I18n.t("login.authenticator_error_fetch_user_details")
      return result
    end

    super(auth, existing_account: existing_account)
  end

  def enabled?
    SiteSetting.bungienet_enabled
  end
end

auth_provider title: "with Bungie.net",
              enabled_setting: "bungienet_enabled",
              message: "Login with Bungie.net",
              frame_width: 920,
              frame_height: 800,
              authenticator: BungienetAuthenticator.new

register_css <<CSS

  button.btn-social.bungienet {
    background-color: #0397d6;
  }

CSS
