require 'spec_helper'
describe 'harden_windows_server' do
  it { is_expected.to compile }
  it { is_expected.to compile.with_all_deps }
end
