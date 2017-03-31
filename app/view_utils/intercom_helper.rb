# coding: utf-8
module IntercomHelper

  CONSOLE_CHECK = "\u{2705} "
  CONSOLE_CROSS = "\u{274c} "
  HTML_CHECK = "\u{2705}&nbsp;"
  HTML_CROSS = "\u{274c}&nbsp;"

  module_function

  # Create a user_hash for Secure mode
  # https://docs.intercom.com/configure-intercom-for-your-product-or-site/staying-secure/enable-secure-mode-on-your-web-product
  def user_hash(user_id)
    secret = APP_CONFIG.admin_intercom_secure_mode_secret
    OpenSSL::HMAC.hexdigest('sha256', secret, user_id) if secret.present?
  end

  def admin_intercom_respond_enabled?
    #
    # Remove the feature flag helper when this is published to everyone
    #
    APP_CONFIG.admin_intercom_respond_enabled.to_s.casecmp("true") &&
      FeatureFlagHelper.feature_enabled?(:admin_intercom_respond)
  end

  def admin_intercom_app_id
    APP_CONFIG.admin_intercom_app_id
  end

  def in_admin_intercom_respond_test_group?
    ratio = (APP_CONFIG.admin_intercom_respond_test_group_ratio || 0).to_f

    Random.rand < ratio
  end

  def email(user_model)
    (user_model.primary_email || user_model.emails.first).address
  end

  def identity_information(user_model)
    marketplace = user_model.community

    {
      info_user_id_old: user_model.id,
      info_marketplace_id: marketplace.uuid_object.to_s,
      info_marketplace_id_old: marketplace.id,
      info_marketplace_url: marketplace.full_url,
      info_email_confirmed: user_model.primary_email.present?
    }
  end

  def verify(conversation_id)
    token = APP_CONFIG.admin_intercom_access_token
    admin_id = APP_CONFIG.admin_intercom_admin_id
    intercom = Intercom::Client.new(token: token)

    conversation = intercom.conversations.find(id: conversation_id)

    if conversation
      puts "#{CONSOLE_CHECK} Found conversation"
    else
      puts "#{CONSOLE_CROSS} Could not find conversation"
      return
    end

    intercom_user = intercom.users.load(conversation.user)

    if intercom_user
      puts "#{CONSOLE_CHECK} Found user"
    else
      puts "#{CONSOLE_CROSS} Could not find user"
      return
    end

    puts "#{CONSOLE_CHECK} Verification done"

    verification_result = do_verification(intercom_user)

    intercom.conversations.reply(id: conversation_id, type: 'admin', admin_id: admin_id, message_type: 'note', body: format_result_html(verification_result))
    puts "#{CONSOLE_CHECK} Verification note sent"

    puts ""
    puts format_result_console(verification_result)

    return verification_result[:passed]
  end

  def format_result_console(verification_result)
    format_result_array(verification_result, CONSOLE_CHECK, CONSOLE_CROSS).join("\n")
  end

  def format_result_html(verification_result)
    format_result_array(verification_result, HTML_CHECK, HTML_CROSS).join("<br />")
  end

  def format_result_array(verification_result, check, cross)
    result =
      if verification_result[:passed]
        "#{check} Identity verified"
      else
        "#{cross} Identity verification FAILED"
      end

    messages = verification_result[:results].map { |res|
      if res[:passed]
        "#{check} #{res[:field_name]}: #{res[:intercom_value]}"
      else
        "#{cross} #{res[:field_name]}: #{res[:intercom_value]} (in database: #{res[:database_value]})"
      end
    }

    [result, ""] + messages
  end

  def find_user_by_uuid(uuid)
    user_uuid_object = UUIDTools::UUID.parse(uuid)
    user_uuid_raw = UUIDUtils.raw(user_uuid_object)

    Person.find_by(uuid: user_uuid_raw)
  end

  def do_verification(intercom_user)
    user_model = find_user_by_uuid(intercom_user.user_id)
    db_user_email = email(user_model)

    verification_results = [
      verify_email(intercom_user, user_model)
    ] + verify_identity_information(intercom_user, user_model)

    {
      passed: verification_results.all? { |v| v[:passed] },
      results: verification_results
    }
  end

  def verify_email(intercom_user, user_model)
    db_user_email = email(user_model)

    {
      passed: intercom_user.email == db_user_email,
      field_name: "email",
      intercom_value: intercom_user.email,
      database_value: db_user_email
    }
  end

  def verify_identity_information(intercom_user, user_model)
    db_identity_information = identity_information(user_model)
    custom_attributes = intercom_user.custom_attributes

    db_identity_information.map { |key, db_value|
      verify_custom_attribute(key, db_value, custom_attributes)
    }
  end

  def verify_custom_attribute(key, db_value, custom_attributes)
    intercom_value = custom_attributes[key]
    {
      passed: db_value == intercom_value,
      field_name: key,
      intercom_value: intercom_value,
      database_value: db_value
    }
  end
end
