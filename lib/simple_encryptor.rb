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
    s
  end


  def check_signature message
    result = message.with_indifferent_access.clone
    signature = result.delete(:signature)
    calculate_signature_raw(result[:identifier], result) == signature
  end

  def check_signature! message
    raise SignatureFailed.new() unless check_signature(message)
  end

  def make_message identifier, payload
    {
      timestamp: Time.now.to_i.to_s,
      identifier: identifier,
      payload: payload
    }
  end


  def encrypt_raw identifier, data
    @cipher.encrypt(secret(identifier), data)
  end

  def decrypt_raw identifier, data
    @cipher.decrypt(secret(identifier), data)
  end

  def calculate_signature_raw identifier, message
    plain = message.to_a.sort_by{|k, _| k.to_s}.map{|pair| pair.join('=')}.join
    Digest::MD5.hexdigest(plain + secret(identifier))
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
