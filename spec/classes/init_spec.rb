require 'spec_helper'
describe 'harden_windows_server' do
  let(:facts) { {'operatingsystem' => 'windows' } }
  #it { is_expected.to compile }
  it {
    should contain_local_security_policy('Enforce password history').with(
      'ensure' => 'present'
    )
  }
  it {
    should contain_local_security_policy('Access this computer from the network').with(
      'ensure' => 'present'
    )
  }
end
