# -*- encoding: utf-8 -*-
$:.push File.expand_path('../lib', __FILE__)
require 'simple_encryptor/version'

Gem::Specification.new do |s|
  s.name        = 'simple_encryptor'
  s.summary     = %q{Simple ecnryption/decryption facility for rails}
  s.description = %q{Simple ecnryption/decryption facility for rails}
  s.version     = SimpleEncryptor::VERSION
  s.platform    = Gem::Platform::RUBY
  s.homepage    = 'https://github.com/RnD-Soft/simple_encryptor'
  s.rubyforge_project = s.name

  s.license     = 'MIT'

  s.authors     = [
    'Samoilenko Yuri',
  ]
  s.email       = [
    'kinnalru@gmail.com',
  ]

  s.files         = `git ls-files`.split("\n")
  s.test_files    = `git ls-files -- spec/*`.split("\n")
  s.require_paths = ['lib']

  s.add_development_dependency 'bundler',     '~> 1.10' # packaging feature
  s.add_development_dependency 'rake',        '~> 10.4' # Tasks manager
  s.add_development_dependency 'rspec-rails', '~> 3.4'
end
