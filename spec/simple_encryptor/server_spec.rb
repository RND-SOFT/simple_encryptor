RSpec.describe SimpleEncryptor::Server, type: :class do
  

  before do

    @store = {
      "client1" => "secret1_loooooooooooooooooooooooooooong",
      "client2" => "secret2_loooooooooooooooooooooooooooong",
    }

    @encryptor = SimpleEncryptor::Server.new({
      store: ->(identifier) {@store[identifier]},
    })
    @encryptor.skip_timestamp = true

    @params = {
      key1: 'hello',
      'key2' => 'hello2'
    }
    @etalon1 = '3d06fa28561910acbe445d2f167d1b87'
    @etalon2 = '5c44dc8ce37a8a9c069bd0f11e7abaf1'


    @etalon_enc1 = "t69gJWOgn0HW5u9HR+7iPw==--6/WbY1MBkZw9NfGAGgRwwg=="
    @etalon_enc2 = "8ATJ2VmdY0O3PUqx37Bl4w==--FBDtswC7SbQii7z2Pz3cUA=="
  end

  it 'server can create and check signature' do

    signature1 = @encryptor.calculate_signature("client1", @params)
    signature2 = @encryptor.calculate_signature("client2", @params)

    expect(@encryptor.secret("client1")).to eq "secret1_loooooooooooooooooooooooooooong"
    expect(@encryptor.secret("client2")).to eq "secret2_loooooooooooooooooooooooooooong"

    expect(signature1).to eq @etalon1
    expect(signature2).to eq @etalon2

    message1 = @params.merge(signature: @etalon1)
    message2 = @params.merge(signature: @etalon2)
    message_invalid = @params.merge(signature: "another")

    expect(@encryptor.check_signature(message1, "client1")).to eq true
    expect(@encryptor.check_signature(message2, "client2")).to eq true

    expect(@encryptor.check_signature(message_invalid, "client1")).to eq false

  end

  it 'server can encrypt and decrypt data' do

    data1 = "data1"
    data2 = "data2"

    dec1 = @encryptor.decrypt("client1", @etalon_enc1)
    dec2 = @encryptor.decrypt("client2", @etalon_enc2)

    expect(dec1).to eq data1
    expect(dec2).to eq data2

    enc1 = @encryptor.encrypt("client1", data1)
    enc2 = @encryptor.encrypt("client2", data2)

    expect(@encryptor.decrypt("client1", enc1)).to eq data1
    expect(@encryptor.decrypt("client2", enc2)).to eq data2


    begin
      @encryptor.decrypt("client1", enc2)
    rescue => e
      expect(e.class).to eq OpenSSL::Cipher::CipherError
    end

    begin
      @encryptor.decrypt("client1", "invalid_enc")
    rescue => e
      expect(e.class).to eq TypeError
    end

  end

  it 'server can encrypt and decrypt messages' do

    data1 = "data1"

    encmessage1 = @encryptor.encrypt_message("client1", data1)

    expect(encmessage1[:identifier]).to eq "client1"
    expect(encmessage1.has_key?(:timestamp)).to eq true
    expect(encmessage1.has_key?(:payload)).to eq true

    decmessage1 = @encryptor.decrypt_message(encmessage1)
    expect(decmessage1[:identifier]).to eq "client1"
    expect(decmessage1.has_key?(:timestamp)).to eq true
    expect(decmessage1[:payload]).to eq data1

  end

  it 'server can encrypt and decrypt signed messages' do

    data1 = "data1"

    encmessage1 = @encryptor.encrypt_message_and_sign("client1", data1)

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

  describe 'server can initialized by' do
    before(:all) do
      class ::Rails
        module VERSION 
          STRING = '4.2.1'
        end

        def self.application
          conf = {simple_encryptor: { 
                    'secret'     => 'secret', 
                    'identifier' => 'identifier' } 
                  }
          def conf.secrets
            self
          end
          conf
        end

      end

    end

    it 'nil' do
      server = SimpleEncryptor::Server.new
      expect(server.secrets_store).to eq 'secret'
      expect(server.options).to       eq({})
    end
    
    it 'only secret' do
      server = SimpleEncryptor::Server.new 'secret2'
      expect(server.secrets_store).to eq 'secret2'
      expect(server.options).to       eq({})
    end
    
    it 'all' do
      opts = { params1: 1}
      server = SimpleEncryptor::Server.new 'secret2', opts
      expect(server.secrets_store).to eq 'secret2'
      expect(server.options).to       eq(opts)
    end
    
  end
end
