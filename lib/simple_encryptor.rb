require 'simple_encryptor/cipher'
require 'simple_encryptor/configure'
require 'simple_encryptor/controller'
require 'simple_encryptor/server'
require 'simple_encryptor/client'

class SimpleEncryptor
  extend Configure

  attr_accessor :ctrl, :cipher

  class SignatureFailed < StandardError; end
  class SecretInvalid < StandardError; end
  class IdentifierInvalid < StandardError; end

  def initialize options
    @cipher = Cipher.new
  end

  def set_controller ctrl
    @ctrl = ctrl
  end

  def calculate_signature_impl secret, params
    sorted = params.to_a.sort_by do |pair|
      k, v = pair
      k.to_s
    end

    plain = sorted.inject("") do |ret, pair|
      k, v = pair
      ret += "#{k.to_s}=#{v.to_s}"
      ret
    end

    return Digest::MD5.hexdigest(plain + secret)
  end

  def check_signature_impl secret, params, signature
    sig = calculate_signature_impl(secret, params)
    return sig == signature
  end

  def check_signature_impl! secret, params, signature
    raise SignatureFailed.new() unless check_signature_impl(secret, params, signature)
  end



private

end
