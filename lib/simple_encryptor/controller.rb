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


  if defined?(Rails) && Rails::VERSION::STRING > "4.2.0"
    class_methods do

      def simple_enc_server secret = nil, options = {}
        @@simple_encryptor = SimpleEncryptor::Server.new(secret, options)

        enryptor_name = options[:encryptor] || :encryptor

        define_method enryptor_name do
          @@simple_encryptor
        end

      end

      def simple_enc_client secret = nil, identifier = nil, options = {}
        @@simple_encryptor = SimpleEncryptor::Client.new(secret, identifier, options)

        enryptor_name = options[:encryptor] || :encryptor

        define_method enryptor_name do
          @@simple_encryptor
        end

      end

    end
  else
    module ClassMethods
      def simple_enc_server options = {}
        self.class_variable_set('@@simple_encryptor', SimpleEncryptor::Server.new(options))
        @@simple_encryptor = self.class_variable_get('@@simple_encryptor')

        enryptor_name = options[:encryptor] || :encryptor

        define_method enryptor_name do
          @@simple_encryptor
        end

      end

      def simple_enc_client options = {}
        self.class_variable_set('@@simple_encryptor', SimpleEncryptor::Client.new(options))
        @@simple_encryptor = self.class_variable_get('@@simple_encryptor')

        enryptor_name = options[:encryptor] || :encryptor

        define_method enryptor_name do
          @@simple_encryptor
        end

      end

    end
  end

end
end
