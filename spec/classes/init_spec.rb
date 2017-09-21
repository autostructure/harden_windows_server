require 'spec_helper'
describe 'harden_windows_server' do
  let(:facts) { {'operatingsystem' => 'windows' } }
  #it { is_expected.to compile }
  let(:params) { { 'is_domain_controller' => false } }
  it {
    should contain_local_security_policy('Enforce password history').with(
      'ensure' => 'present',
      'policy_setting' => 'PasswordHistorySize',
      'policy_type' => 'System Access',
      'policy_value' => '24'
    )
  }
  it {
    should contain_local_security_policy('Maximum password age').with(
      'ensure'         => 'present',
      'policy_setting' => 'MaximumPasswordAge',
      'policy_type'    => 'System Access',
      'policy_value'   => '42'
    )
  }
  it {
    should contain_local_security_policy('Minimum password age').with(
      'ensure'         => 'present',
      'policy_setting' => 'MinimumPasswordAge',
      'policy_type'    => 'System Access',
      'policy_value'   => '1'
    )
  }
  it {
    should contain_local_security_policy('Minimum password length').with(
      'ensure'         => 'present',
      'policy_setting' => 'MinimumPasswordLength',
      'policy_type'    => 'System Access',
      'policy_value'   => '14'
    )
  }
  it {
    should contain_local_security_policy('Password must meet complexity requirements').with(
      'ensure'         => 'present',
      'policy_setting' => 'PasswordComplexity',
      'policy_type'    => 'System Access',
      'policy_value'   => '1'
    )
  }
  it {
    should contain_local_security_policy('Store passwords using reversible encryption').with(
      'ensure'         => 'present',
      'policy_setting' => 'ClearTextPassword',
      'policy_type'    => 'System Access',
      'policy_value'   => '0'
    )
  }
  it {
    should contain_local_security_policy('Account lockout duration').with(
      'ensure'         => 'present',
      'policy_setting' => 'LockoutDuration',
      'policy_type'    => 'System Access',
      'policy_value'   => '30'
    )
  }
  it {
    should contain_local_security_policy('Account lockout threshold').with(
      'ensure'         => 'present',
      'policy_setting' => 'LockoutBadCount',
      'policy_type'    => 'System Access',
      'policy_value'   => '10'
    )
  }
  it {
    should contain_local_security_policy('Reset account lockout counter after').with(
      'ensure'         => 'present',
      'policy_setting' => 'ResetLockoutCount',
      'policy_type'    => 'System Access',
      'policy_value'   => '30'
    )
  }
  it {
    should contain_local_security_policy('Access Credential Manager as a trusted caller').with(
      'ensure'         => 'absent'
    )
  }
  it {
    should contain_local_security_policy('Access this computer from the network').with(
      'ensure'         => 'present',
      'policy_setting' => 'SeNetworkLogonRight',
      'policy_type'    => 'Privilege Rights',
      'policy_value'   => '*S-1-5-32-544,*S-1-5-11'
    )
  }
  it {
    should contain_local_security_policy('Act as part of the operating system').with(
      'ensure'         => 'absent'
    )
  }
  # it {
  #   should contain_local_security_policy('Add workstations to domain').with(
  #     'ensure'         => 'absent'
  #   )
  # }
  it {
    should contain_local_security_policy('Adjust memory quotas for a process').with(
      'ensure'         => 'present',
      'policy_setting' => 'SeIncreaseQuotaPrivilege',
      'policy_type'    => 'Privilege Rights',
      'policy_value'   => '*S-1-5-19,*S-1-5-20,*S-1-5-32-544'
    )
  }
  it {
    should contain_local_security_policy('Allow log on locally').with(
      'ensure'         => 'present',
      'policy_setting' => 'SeInteractiveLogonRight',
      'policy_type'    => 'Privilege Rights',
      'policy_value'   => '*S-1-5-32-544'
    )
  }
  it {
    should contain_local_security_policy('Allow log on through Remote Desktop Services').with(
      'ensure'         => 'present',
      'policy_setting' => 'SeRemoteInteractiveLogonRight',
      'policy_type'    => 'Privilege Rights',
      'policy_value'   => '*S-1-5-32-544,*S-1-5-32-555'
    )
  }
  it {
    should contain_local_security_policy('Back up files and directories').with(
      'ensure'         => 'present',
      'policy_setting' => 'SeBackupPrivilege',
      'policy_type'    => 'Privilege Rights',
      'policy_value'   => '*S-1-5-32-544'
    )
  }
  it {
    should contain_local_security_policy('Change the system time').with(
      'ensure'         => 'present',
      'policy_setting' => 'SeSystemtimePrivilege',
      'policy_type'    => 'Privilege Rights',
      'policy_value'   => '*S-1-5-19,*S-1-5-32-544'
    )
  }
  it {
    should contain_local_security_policy('Change the time zone').with(
      'ensure'         => 'present',
      'policy_setting' => 'SeTimeZonePrivilege',
      'policy_type'    => 'Privilege Rights',
      'policy_value'   => '*S-1-5-19,*S-1-5-32-544'
    )
  }
  it {
    should contain_local_security_policy('Create a pagefile').with(
      'ensure'         => 'present',
      'policy_setting' => 'SeCreatePagefilePrivilege',
      'policy_type'    => 'Privilege Rights',
      'policy_value'   => '*S-1-5-32-544'
    )
  }
  it {
    should contain_local_security_policy('Create a token object').with(
      'ensure'         => 'absent'
    )
  }
  it {
    should contain_local_security_policy('Create global objects').with(
      'ensure'         => 'present',
      'policy_setting' => 'SeCreateGlobalPrivilege',
      'policy_type'    => 'Privilege Rights',
      'policy_value'   => '*S-1-5-19,*S-1-5-20,*S-1-5-32-544,*S-1-5-6'
    )
  }
  it {
    should contain_local_security_policy('Create permanent shared objects').with(
      'ensure'         => 'absent'
    )
  }
  it {
    should contain_local_security_policy('Create symbolic links').with(
      'ensure'         => 'present',
      'policy_setting' => 'SeCreateSymbolicLinkPrivilege',
      'policy_type'    => 'Privilege Rights',
      'policy_value'   => '*S-1-5-32-544,*S-1-5-83-0'
    )
  }
  it {
    should contain_local_security_policy('Debug programs').with(
      'ensure'         => 'present',
      'policy_setting' => 'SeDebugPrivilege',
      'policy_type'    => 'Privilege Rights',
      'policy_value'   => '*S-1-5-32-544'
    )
  }
  it {
    should contain_local_security_policy('Deny access to this computer from the network').with(
      'ensure'         => 'present',
      'policy_setting' => 'SeDenyNetworkLogonRight',
      'policy_type'    => 'Privilege Rights',
      'policy_value'   => '*S-1-5-32-546'
    )
  }
  it {
    should contain_local_security_policy('Deny log on as a batch job').with(
      'ensure'         => 'present',
      'policy_setting' => 'SeDenyBatchLogonRight',
      'policy_type'    => 'Privilege Rights',
      'policy_value'   => '*S-1-5-32-546'
    )
  }
  it {
    should contain_local_security_policy('Deny log on as a service').with(
      'ensure'         => 'present',
      'policy_setting' => 'SeDenyServiceLogonRight',
      'policy_type'    => 'Privilege Rights',
      'policy_value'   => '*S-1-5-32-546'
    )
  }
  it {
    should contain_local_security_policy('Deny log on locally').with(
      'ensure'         => 'present',
      'policy_setting' => 'SeDenyInteractiveLogonRight',
      'policy_type'    => 'Privilege Rights',
      'policy_value'   => '*S-1-5-32-546'
    )
  }
  it {
    should contain_local_security_policy('Deny log on through Remote Desktop Services').with(
      'ensure'         => 'present',
      'policy_setting' => 'SeDenyRemoteInteractiveLogonRight',
      'policy_type'    => 'Privilege Rights',
      'policy_value'   => '*S-1-5-32-546'
    )
  }
  it {
    should contain_local_security_policy('Enable computer and user accounts to be trusted for delegation').with(
      'ensure'         => 'absent'
    )
  }
  it {
    should contain_local_security_policy('Force shutdown from a remote system').with(
      'ensure'         => 'present',
      'policy_setting' => 'SeRemoteShutdownPrivilege',
      'policy_type'    => 'Privilege Rights',
      'policy_value'   => '*S-1-5-32-544'
    )
  }
  it {
    should contain_local_security_policy('Generate security audits').with(
      'ensure'         => 'present',
      'policy_setting' => 'SeAuditPrivilege',
      'policy_type'    => 'Privilege Rights',
      'policy_value'   => '*S-1-5-19,*S-1-5-20'
    )
  }
  it {
    should contain_local_security_policy('Impersonate a client after authentication').with(
      'ensure'         => 'present',
      'policy_setting' => 'SeImpersonatePrivilege',
      'policy_type'    => 'Privilege Rights',
      'policy_value'   => '*S-1-5-19,*S-1-5-20,*S-1-5-32-544,*S-1-5-6,*S-1-5-17'
    )
  }
  it {
    should contain_local_security_policy('Increase scheduling priority').with(
      'ensure'         => 'present',
      'policy_setting' => 'SeIncreaseBasePriorityPrivilege',
      'policy_type'    => 'Privilege Rights',
      'policy_value'   => '*S-1-5-32-544'
    )
  }
  it {
    should contain_local_security_policy('Load and unload device drivers').with(
      'ensure'         => 'present',
      'policy_setting' => 'SeLoadDriverPrivilege',
      'policy_type'    => 'Privilege Rights',
      'policy_value'   => '*S-1-5-32-544'
    )
  }









  it {
    should contain_local_security_policy('Access this computer from the network').with(
      'ensure' => 'present'
    )
  }
end
