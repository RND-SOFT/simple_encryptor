class SimpleEncryptor
class Cipher

  def initialize
    @aes_enc = OpenSSL::Cipher::Cipher.new('aes-256-cbc').encrypt
    @aes_dec = OpenSSL::Cipher::Cipher.new('aes-256-cbc').decrypt
  end 

  def encrypt(key, text)
    @aes_enc.key = key
    iv = @aes_enc.random_iv
    @aes_enc.iv = iv

    enciphered = @aes_enc.update(text) << @aes_enc.final

    return [enciphered, iv].map { |part| [part].pack('m').gsub(/\n/, '') }.join('--')
  end

  def decrypt(key, text)
    enciphered, iv = text.split('--', 2).map { |part| part.unpack('m')[0] }
    @aes_dec.key = key
    @aes_dec.iv = iv

    return @aes_dec.update(enciphered) << @aes_dec.final
  end

end
end
