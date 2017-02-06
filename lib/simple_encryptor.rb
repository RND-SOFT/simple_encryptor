require 'simple_encryptor/cipher'
require 'simple_encryptor/configure'
require 'simple_encryptor/controller'
require 'simple_encryptor/server'
require 'simple_encryptor/client'

class SimpleEncryptor
  extend Configure

  attr_accessor :ctrl, :cipher, :options, :skip_timestamp
  attr_accessor :secrets_store

  class SignatureFailed < StandardError; end
  class SecretInvalid < StandardError; end
  class IdentifierInvalid < StandardError; end

  def initialize *args
    @cipher = Cipher.new
    @options = {}
    @skip_timestamp = false
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
    calc_sig = calculate_signature_raw(result[:identifier], result)
    ts = Time.at(result[:timestamp].to_i) rescue Time.at(0)
    ts_ok = ts.between?(Time.now - 2 * 60, Time.now + 2 * 60)
    calc_sig == signature and ( @skip_timestamp || ts_ok )
  end

  def check_signature! *args
    raise SignatureFailed.new() unless check_signature(*args)
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
    Digest::MD5.hexdigest(normalize_hash(message) + secret(identifier))
  end

  def normalize_hash hash
    hash.to_a.sort_by{|k, _| k.to_s}.map do |k, v|
      v = normalize_hash(v) if v.is_a?(Hash)
      [k, v].join("=")
    end.join
  end

  def create_store store
    @secrets_store = make_callable(store)
  end

  def make_callable obj
    if obj.is_a? String
      obj
    elsif obj.is_a? Symbol
      -> (identifier){ @ctrl.send(obj, identifier) }
    elsif obj.respond_to? :call 
      obj
    elsif obj.is_a? Class
      -> (identifier){ obj.new.secret(identifier) }
    end
  end

  def rails_secrets
    return {} unless defined?(Rails) and Rails::VERSION::STRING > "4.1.0"
    config_key = options[:config_key] || :simple_encryptor
    Rails.application.secrets.fetch( config_key, {})
  end

end
