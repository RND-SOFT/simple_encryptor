require 'simple_encryptor/cipher'
require 'simple_encryptor/configure'
require 'simple_encryptor/controller'
require 'simple_encryptor/server'
require 'simple_encryptor/client'

class SimpleEncryptor
  extend Configure

  attr_accessor :ctrl, :cipher, :options
  attr_accessor :secrets_store

  class SignatureFailed < StandardError; end
  class SecretInvalid < StandardError; end
  class IdentifierInvalid < StandardError; end

  def initialize options
    @cipher = Cipher.new
    @options = options
  end

  def set_controller ctrl
    @ctrl = ctrl
  end

  def secret identifier
    s = (@secrets_store.is_a?(String) ? @secrets_store : @secrets_store.call(identifier))
    raise SecretInvalid.new("cannot be blank") if s.blank?
    return s
  end


  def check_signature message
    result = message.with_indifferent_access.clone
    signature = result.delete(:signature)
    return calculate_signature_raw(result[:identifier], result) == signature
  end

  def check_signature! message
    raise SignatureFailed.new() unless check_signature(message)
  end

  def make_message identifier, payload
    return {
      timestamp: Time.now.to_i.to_s,
      identifier: identifier,
      payload: payload
    }
  end


  def encrypt_raw identifier, data
    return @cipher.encrypt(secret(identifier), data)
  end

  def decrypt_raw identifier, data
    return @cipher.decrypt(secret(identifier), data)
  end

  def calculate_signature_raw identifier, message
    sorted = message.to_a.sort_by do |k, v|
      k.to_s
    end

    plain = sorted.map{|pair| pair.join('=')}.join

    return Digest::MD5.hexdigest(plain + secret(identifier))
  end



  def create_store store
    @secrets_store = if store.is_a? String
      store
    elsif store.is_a? Symbol
      -> (identifier){@ctrl.send(store, identifier)}
    elsif store.respond_to? :call 
      store
    elsif store.is_a? Class
      s = new store
      -> (identifier){s.secret(identifier)}
    end
  end

end
