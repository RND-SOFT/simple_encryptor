require 'simple_encryptor/configure'
require 'simple_encryptor/controller'
require 'simple_encryptor/railtie' if defined?(Rails)

class SimpleEncryptor
  extend Configure

  attr_accessor :secrets_store, :ctrl

  def initialize options
    create_store options[:store]
  end

  def set_controller ctrl
    @ctrl = ctrl
  end

  def secret identifier
    return @secrets_store.call(identifier)
  end




private

    def create_store store
      @secrets_store = if store.is_a? String
        -> (identifier){store}
      elsif store.is_a? Symbol
        -> (identifier){@ctrl.send(store, identifier)}
      elsif store.respond_to? :call 
        store
      elsif store.is_a? Class
        new store
      end
    end

end
