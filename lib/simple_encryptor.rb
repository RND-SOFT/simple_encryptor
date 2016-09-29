require 'simple_encryptor/cipher'
require 'simple_encryptor/configure'
require 'simple_encryptor/controller'
require 'simple_encryptor/server'
require 'simple_encryptor/client'

class SimpleEncryptor
  extend Configure

  attr_accessor :ctrl, :cipher, :options

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

  def calculate_signature_impl secret, params
    plain = params.to_a.sort_by{|k, _| k.to_s }.map{|k, v| "#{k}=#{v}" }.join
    Digest::MD5.hexdigest(plain + secret)
  end

  def make_message payload
    return {
      timestamp: Time.now.to_i.to_s,
      identifier: @identifier,
      payload: payload
    }
  end

  def check_signature_impl secret, params, signature
    sig = calculate_signature_impl(secret, params)
    sig == signature
  end

  def check_signature_impl! secret, params, signature
    raise SignatureFailed.new() unless check_signature_impl(secret, params, signature)
  end



private

end
