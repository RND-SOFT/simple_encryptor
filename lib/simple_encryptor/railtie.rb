require 'simple_encryptor'
require 'rails'

module SimpleEncryptor
  class Railtie < Rails::Railtie
    initializer 'simple_encryptor.initialize' do
      ActiveSupport.on_load(:active_record) do
        ActiveRecord::Base.send :extend, SimpleEncryptor
      end
      
    end
  end
end
