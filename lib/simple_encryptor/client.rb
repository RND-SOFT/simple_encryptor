
class SimpleEncryptor
class Client < SimpleEncryptor

  attr_accessor :response_param_name, :identifier

  def initialize secret = nil, identifier = nil, options = {}
    super
    @options = options
    if secret.is_a?(Hash)
      secret, identifier, @options = nil, nil, secret
    end

    if secret.present? and identifier.is_a?(Hash)
      identifier, @options = nil, identifier
    end

    @identifier = identifier || @options[:identifier] || rails_secrets['identifier']
    raise IdentifierInvalid.new("cannot be blank") if @identifier.blank?

    @identifier = make_callable(@identifier)

    secret ||= @options[:secret] || rails_secrets['secret']
    raise SecretInvalid.new("cannot be blank") if secret.blank?
    create_store secret

    @response_param_name = (@options[:param_name] || :encrypted_response).to_s
  end

  def encrypt data
    encrypt_raw @identifier, data
  end

  def decrypt data
    decrypt_raw @identifier, data
  end

  def calculate_signature message
    calculate_signature_raw @identifier, message
  end

  def encrypt_message payload
    make_message @identifier, encrypt(payload.is_a?(String) ? payload : payload.to_json)
  end

  def encrypt_message_and_sign payload
    result = encrypt_message(payload)
    result[:signature] = calculate_signature(result)
    result
  end


  def decrypt_message message
    result = message.with_indifferent_access.clone
    raise IdentifierInvalid.new("'#{result[:identifier]}' != '#{@identifier}'") if result[:identifier] != @identifier
    decrypted = decrypt result[:payload]
    result[:payload] = JSON.parse(decrypted) rescue decrypted
    result
  end

  def decrypt_signed_message message
    check_signature!(message)
    decrypt_message(message)
  end

  def receive response
    decrypt_signed_message(response[@response_param_name]) if response[@response_param_name]
  end


private


end
end
