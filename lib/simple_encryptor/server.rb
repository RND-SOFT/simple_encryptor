
class SimpleEncryptor
class Server < SimpleEncryptor

  attr_accessor :request_param_name

  def initialize store = nil, options = {}
    super
    @options = options
    if store.is_a? Hash 
      store, @options = nil, store
    end

    create_store(store || @options[:store] || rails_secrets['secret'])
    @request_param_name = (@options[:param_name] || :encrypted_message).to_s
  end

  def encrypt identifier, data
    encrypt_raw identifier, data
  end

  def decrypt identifier, data
    decrypt_raw identifier, data
  end

  def calculate_signature identifier, message
    calculate_signature_raw identifier, message
  end

  def check_signature message, identifier = nil
    if identifier.nil?
      super(message)
    else
      result = message.with_indifferent_access.clone
      signature = result.delete(:signature)
      calculate_signature_raw(identifier, result) == signature
    end
  end

  def check_signature! *args
    raise SignatureFailed.new() unless check_signature(*args)
  end


  def sign_message identifier, payload
    make_message identifier, calculate_signature(identifier, payload)
  end

  def sign_message identifier, payload
    result = make_message(identifier, payload)
    result[:signature] = calculate_signature(identifier, result)
    result
  end

  def encrypt_message identifier, payload
    make_message identifier, encrypt(identifier, payload.is_a?(String) ? payload : payload.to_json)
  end

  def encrypt_message_and_sign identifier, payload
    result = encrypt_message(identifier, payload)
    result[:signature] = calculate_signature(identifier, result)
    result
  end


  def decrypt_message message
    result = message.with_indifferent_access.clone
    decrypted = decrypt(result[:identifier], result[:payload])
    result[:payload] = JSON.parse(decrypted) rescue decrypted
    result
  end

  def decrypt_signed_message message
    check_signature!(message)
    decrypt_message(message)
  end


  def request_valid? request_params
    check_signature(request_params[@request_param_name]) if request_params[@request_param_name]
  end

  def receive! request_params, *args
    decrypt_signed_message(request_params[@request_param_name], *args) if request_params[@request_param_name]
  end

  def receive *args
    receive!(*args) rescue nil
  end

private



end
end
