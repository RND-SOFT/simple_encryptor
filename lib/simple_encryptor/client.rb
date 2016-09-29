
class SimpleEncryptor
class Client < SimpleEncryptor

  attr_accessor :secret

  def initialize options
    super
    @secret = options[:secret]
    @identifier = options[:identifier]
    raise SecretInvalid.new() if @secret.blank?
    raise IdentifierInvalid.new() if @identifier.blank?
  end

  def encrypt data
    return @cipher.encrypt(@secret, data)
  end

  def decrypt data
    return @cipher.decrypt(@secret, data)
  end

  def calculate_signature params
    return calculate_signature_impl(@secret, params)
  end

  def check_signature params, signature
    return check_signature_impl(@secret, params, signature)
  end

  def check_signature! params, signature
    return check_signature_impl!(@secret, params, signature)
  end

  def encrypt_message payload
    return make_message encrypt(payload)
  end

  def decrypt_message message
    result = message.with_indifferent_access.clone
    result[:payload] = decrypt(result[:payload])
    return result
  end

  def encrypt_message_and_sign payload
    payload = encrypt_message(payload)
    payload[:signature] = calculate_signature(payload)
    return payload
  end

  def decrypt_signed_message message
    result = message.with_indifferent_access.clone
    signature = result.delete(:signature)
    check_signature!(result, signature)
    result[:payload] = decrypt(result[:payload])
    return result
  end


private


end
end
