require_relative './ipa_reader.rb'

ipa = IpaReader.new("ipa.example.com")
puts ipa.user.list
puts ipa.user.show('hewhowas')