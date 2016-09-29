
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
    @cipher.encrypt(@secret, data)
  end

  def decrypt data
    @cipher.decrypt(@secret, data)
  end

  def calculate_signature params
    calculate_signature_impl(@secret, params)
  end

  def check_signature params, signature
    check_signature_impl(@secret, params, signature)
  end

  def check_signature! params, signature
    check_signature_impl!(@secret, params, signature)
  end

  def encrypt_message payload
    {
      timestamp: Time.now.to_i.to_s,
      identifier: @identifier,
      payload: encrypt(payload)
    }
  end

  def decrypt_message message
    result = message.clone
    result[:payload] = decrypt(result[:payload])
    result
  end

  def encrypt_message_and_sign payload
    payload = encrypt_message(payload)
    payload[:signature] = calculate_signature(payload)
    payload
  end

  def decrypt_signed_message message
    result = message.clone
    signature = result.delete(:signature)
    check_signature!(result, signature)
    result[:payload] = decrypt(result[:payload])
    result
  end


private


end
end
