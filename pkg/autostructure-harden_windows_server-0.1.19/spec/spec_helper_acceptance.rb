require 'beaker-rspec'

hosts.each do |host|
  install_puppet_agent_on(hosts)
end

RSpec.configure do |c|
  # Project root
  proj_root = File.expand_path(File.join(File.dirname(__FILE__), '..'))

  # Readable test descriptions
  c.formatter = :documentation

  # Configure all nodes in nodeset
  c.before :suite do
    # Install module and dependencies
    puppet_module_install(:source => proj_root, :module_name => 'harden_windows_server')
    hosts.each do |host|
      # Needed for the consul module to download the binary per the modulefile
      on host, puppet('module', 'install', 'puppetlabs-stdlib'), { :acceptable_exit_codes => [0,1] }
      on host, puppet('module', 'install', 'puppetlabs-registry'), { :acceptable_exit_codes => [0,1] }
      on host, puppet('module', 'install', 'ayohrling-local_security_policy'), { :acceptable_exit_codes => [0,1] }
    end
  end
end
