class SimpleEncryptor
module Controller
  extend ActiveSupport::Concern

  @@simple_encryptor = nil

  included do

    def initialize *args
      super
      @@simple_encryptor.set_controller(self) if @@simple_encryptor
    end

  end

  class_methods do

    def simple_enc_server options = {}
      @@simple_encryptor = SimpleEncryptor::Server.new(options)

      enryptor_name = options[:encryptor] || :encryptor

      define_method enryptor_name do
        @@simple_encryptor
      end

    end

    def simple_enc_client options = {}
      @@simple_encryptor = SimpleEncryptor::Client.new(options)

      enryptor_name = options[:encryptor] || :encryptor

      define_method enryptor_name do
        @@simple_encryptor
      end

    end

  end

end
end
