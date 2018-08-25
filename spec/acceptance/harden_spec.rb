# module_root/spec/acceptance/standard_spec.rb
require 'spec_helper_acceptance'

describe 'init class' do
  context 'default parameters' do
    # Using puppet_apply as a helper
    it 'works with no errors based on the example' do
      pp = <<-PP
        class { 'harden_windows_server': }
      PP

      # Run it twice and test for idempotency

      apply_manifest(pp, catch_failures: true)
      expect(apply_manifest(pp, catch_failures: true).exit_code).to be_zero

      # expect(apply_manifest(pp).exit_code).to_not eq(1)
      # expect(apply_manifest(pp).exit_code).to eq(0)
    end
  end
end
