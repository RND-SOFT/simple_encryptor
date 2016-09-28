# simple_encryptor
Simple ecnryption/decryption facility for secure rails servers interaction. One of the server is a Client and other is Server. 

### Client
Client means a server which call API of the server. It has own **identifier** and **secret** shared with API server.

### Server
Server means a server whose API can be called by multiple client. Server must share **identifiers** and **secrets** with all clients. Identifier and Secret generation, distribution and maintaining is out of SimpleEncryptor responsibility.


## Configure your controller

```ruby
class ApplicationController < ActionController::Base
  simple_enc_server store: :get_from_secrets , encryptor: :encryptor

  def get_from_secrets(identifier)
    return Rails.application.secrets.clients['identifier']
  end
end
```

## Options for get_from_secrets

### store
Store can be Symbol, Block or Class. Block is called with **identifier** argument: 
```ruby
  simple_enc_server store: ->(identifier){return "SECRET"}
```
Class must implement ```secret``` function with returns **secret** for passed **identifier**. In case of symbol this method of the controller called when **secret** must be obtained for identifier. 


### encryptor
This is name of the SimpleEncryptor object attached for the controller. Default is ```encryptor```:

```ruby
class ApplicationController < ActionController::Base
  simple_enc_server store: :get_from_secrets , encryptor: :my_encryptor

  def some_action
    puts my_encryptor.secret("CLIENT_ID")
  end
end
```

