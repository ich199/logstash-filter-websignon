Gem::Specification.new do |s|
  s.name = 'logstash-filter-websignon'
  s.version         = '6.0.0'
  s.licenses = ['Apache-2.0']
  s.summary = "This filter queries websignon to retrieve user details from a given username."
  s.description     = "This gem is a Logstash plugin required to be installed on top of the Logstash core pipeline using $LS_HOME/bin/logstash-plugin install gemname. This gem is not a stand-alone program"
  s.authors = ["Iain Hammond"]
  s.email = 'i.hammond@warwick.ac.uk'
  s.homepage = "http://www.elastic.co/guide/en/logstash/current/index.html"
  s.require_paths = ["lib"]

  # Files
  s.files = Dir['lib/**/*','spec/**/*','vendor/**/*','*.gemspec','*.md','CONTRIBUTORS','Gemfile','LICENSE','NOTICE.TXT']
  # Tests
  s.test_files = s.files.grep(%r{^(test|spec|features)/})

  # Special flag to let us know this is actually a logstash plugin
  s.metadata = { "logstash_plugin" => "true", "logstash_group" => "filter" }

  # Gem dependencies
  #s.add_runtime_dependency "logstash-core-plugin-api", ">= 1.4.0", "< 2.0.0"
  s.add_runtime_dependency "logstash-core-plugin-api", "~> 2.0"
  s.add_runtime_dependency "lru_redux", "1.1.0"
  s.add_runtime_dependency "httpclient", "2.6.0.1"

  s.add_development_dependency 'logstash-devutils'
  #s.add_development_dependency "timecop", "~> 0.7"
end
