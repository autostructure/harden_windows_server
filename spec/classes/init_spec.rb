require 'spec_helper'
describe 'harden_windows_server' do
  let(:facts) { { :operatingsystem => 'windows' } }
  it { is_expected.to compile }
end
