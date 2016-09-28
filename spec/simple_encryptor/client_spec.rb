RSpec.describe SimpleEncryptor::Client, type: :class do
  

  before do

    @encryptor = SimpleEncryptor::Client.new({
      identifier: 'client1',
      secret: 'secret1_loooooooooooooooooooooooooooong',
    })

    @params = {
      key1: 'hello',
      'key2' => 'hello2'
    }
    @etalon1 = '3d06fa28561910acbe445d2f167d1b87'

    @etalon_enc1 = "t69gJWOgn0HW5u9HR+7iPw==--6/WbY1MBkZw9NfGAGgRwwg=="
    @etalon_enc2 = "8ATJ2VmdY0O3PUqx37Bl4w==--FBDtswC7SbQii7z2Pz3cUA=="
  end

  it 'client can create and check signature' do

    signature1 = @encryptor.calculate_signature(@params)

    expect(signature1).to eq @etalon1
    expect(@encryptor.check_signature(@params, @etalon1)).to eq true
    expect(@encryptor.check_signature(@params, "another")).to eq false

  end

  it 'client can encrypt and decrypt data' do

    data1 = "data1"

    dec1 = @encryptor.decrypt(@etalon_enc1)

    expect(dec1).to eq data1

    enc1 = @encryptor.encrypt(data1)
    expect(@encryptor.decrypt(enc1)).to eq data1


    begin
      @encryptor.decrypt(@etalon_enc2)
    rescue => e
      expect(e.class).to eq OpenSSL::Cipher::CipherError
    end

    begin
      @encryptor.decrypt("invalid_enc")
    rescue => e
      expect(e.class).to eq TypeError
    end

  end

  it 'client can encrypt and decrypt messages' do

    data1 = "data1"

    encmessage1 = @encryptor.encrypt_message(data1)

    expect(encmessage1[:identifier]).to eq "client1"
    expect(encmessage1.has_key?(:timestamp)).to eq true
    expect(encmessage1.has_key?(:payload)).to eq true

    decmessage1 = @encryptor.decrypt_message(encmessage1)
    expect(decmessage1[:identifier]).to eq "client1"
    expect(decmessage1.has_key?(:timestamp)).to eq true
    expect(decmessage1[:payload]).to eq data1

  end

  it 'client can encrypt and decrypt signed messages' do

    data1 = "data1"

    encmessage1 = @encryptor.encrypt_message_and_sign(data1)

    expect(encmessage1[:identifier]).to eq "client1"
    expect(encmessage1.has_key?(:timestamp)).to eq true
    expect(encmessage1.has_key?(:payload)).to eq true
    expect(encmessage1.has_key?(:signature)).to eq true

    decmessage1 = @encryptor.decrypt_signed_message(encmessage1)
    expect(decmessage1[:identifier]).to eq "client1"
    expect(decmessage1.has_key?(:timestamp)).to eq true
    expect(decmessage1[:payload]).to eq data1


    encmessage1[:signature] += "11111111561910acbe445d2f167d1111"

    begin
      decmessage1 = @encryptor.decrypt_signed_message(encmessage1)
    rescue => e 
      expect(e.class).to eq SimpleEncryptor::SignatureFailed
    end
    
  end

end
