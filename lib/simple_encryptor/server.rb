
class SimpleEncryptor
class Server < SimpleEncryptor

  attr_accessor :secrets_store

  def initialize options
    super
    create_store options[:store]
  end

  def secret identifier
    s = @secrets_store.call(identifier)
    raise SecretInvalid.new() if s.blank?
    return s
  end

  def encrypt identifier, data
    return @cipher.encrypt(secret(identifier), data)
  end

  def decrypt identifier, data
    return @cipher.decrypt(secret(identifier), data)
  end

  def calculate_signature identifier, params
    return calculate_signature_impl(secret(identifier), params)
  end

  def check_signature identifier, params, signature
    return check_signature_impl(secret(identifier), params, signature)
  end

  def check_signature! identifier, params, signature
    return check_signature_impl!(secret(identifier), params, signature)
  end

  def encrypt_message identifier, payload
    return {
      timestamp: Time.now.to_i.to_s,
      identifier: identifier,
      payload: encrypt(identifier, payload)
    }
  end

  def decrypt_message message
    result = message.clone
    result[:payload] = decrypt(result[:identifier], result[:payload])
    return result
  end

  def encrypt_message_and_sign identifier, payload
    payload = encrypt_message(identifier, payload)
    payload[:signature] = calculate_signature(identifier, payload)
    return payload
  end

  def decrypt_signed_message message
    result = message.clone
    signature = result.delete(:signature)
    check_signature!(result[:identifier], result, signature)
    result[:payload] = decrypt(result[:identifier], result[:payload])
    return result
  end


private

    def create_store store
      @secrets_store = if store.is_a? String
        -> (identifier){store}
      elsif store.is_a? Symbol
        -> (identifier){@ctrl.send(store, identifier)}
      elsif store.respond_to? :call 
        store
      elsif store.is_a? Class
        new store
      end
    end

end
end
