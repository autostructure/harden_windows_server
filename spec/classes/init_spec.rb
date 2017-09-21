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
    should contain_local_security_policy('Lock pages in memory').with(
      'ensure'         => 'absent'
    )
  }
  # it {
  #   should contain_local_security_policy('Log on as a batch job').with(
  #     'ensure'         => 'absent'
  #   )
  # }
  it {
    should contain_local_security_policy('Manage auditing and security log').with(
      'ensure'         => 'present',
      'policy_setting' => 'SeSecurityPrivilege',
      'policy_type'    => 'Privilege Rights',
      'policy_value'   => '*S-1-5-32-544'
    )
  }
  it {
    should contain_local_security_policy('Modify an object label').with(
      'ensure'         => 'absent'
    )
  }
  it {
    should contain_local_security_policy('Modify firmware environment values').with(
      'ensure'         => 'present',
      'policy_setting' => 'SeSystemEnvironmentPrivilege',
      'policy_type'    => 'Privilege Rights',
      'policy_value'   => '*S-1-5-32-544'
    )
  }
  it {
    should contain_local_security_policy('Perform volume maintenance tasks').with(
      'ensure'         => 'present',
      'policy_setting' => 'SeManageVolumePrivilege',
      'policy_type'    => 'Privilege Rights',
      'policy_value'   => '*S-1-5-32-544'
    )
  }
  it {
    should contain_local_security_policy('Profile single process').with(
      'ensure'         => 'present',
      'policy_setting' => 'SeProfileSingleProcessPrivilege',
      'policy_type'    => 'Privilege Rights',
      'policy_value'   => '*S-1-5-32-544'
    )
  }
  it {
    should contain_local_security_policy('Profile system performance').with(
      'ensure'         => 'present',
      'policy_setting' => 'SeSystemProfilePrivilege',
      'policy_type'    => 'Privilege Rights',
      'policy_value'   => '*S-1-5-32-544,*S-1-5-80-3139157870-2983391045-3678747466-658725712-1809340420'
    )
  }
  it {
    should contain_local_security_policy('Replace a process level token').with(
      'ensure'         => 'present',
      'policy_setting' => 'SeAssignPrimaryTokenPrivilege',
      'policy_type'    => 'Privilege Rights',
      'policy_value'   => '*S-1-5-19,*S-1-5-20'
    )
  }
  it {
    should contain_local_security_policy('Restore files and directories').with(
      'ensure'         => 'present',
      'policy_setting' => 'SeRestorePrivilege',
      'policy_type'    => 'Privilege Rights',
      'policy_value'   => '*S-1-5-32-544'
    )
  }
  it {
    should contain_local_security_policy('Shut down the system').with(
      'ensure'         => 'present',
      'policy_setting' => 'SeShutdownPrivilege',
      'policy_type'    => 'Privilege Rights',
      'policy_value'   => '*S-1-5-32-544'
    )
  }
  it {
    should contain_local_security_policy('Take ownership of files or other objects').with(
      'ensure'         => 'present',
      'policy_setting' => 'SeTakeOwnershipPrivilege',
      'policy_type'    => 'Privilege Rights',
      'policy_value'   => '*S-1-5-32-544'
    )
  }
  it {
    should contain_local_security_policy('Accounts: Limit local account use of blank passwords to console logon only').with(
      'ensure'         => 'present',
      'policy_setting' => 'MACHINE\System\CurrentControlSet\Control\Lsa\LimitBlankPasswordUse',
      'policy_type'    => 'Registry Values',
      'policy_value'   => '4,1'
    )
  }
  it {
    should contain_local_security_policy('Accounts: Rename administrator account').with(
      'ensure'         => 'present',
      'policy_setting' => 'NewAdministratorName',
      'policy_type'    => 'System Access',
      'policy_value'   => '"Administrator"'
    )
  }
  it {
    should contain_local_security_policy('Accounts: Rename guest account').with(
      'ensure'         => 'present',
      'policy_setting' => 'NewGuestName',
      'policy_type'    => 'System Access',
      'policy_value'   => '"Guest"'
    )
  }
  it {
    should contain_local_security_policy('Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings').with(
      'ensure'         => 'present',
      'policy_setting' => 'MACHINE\System\CurrentControlSet\Control\Lsa\SCENoApplyLegacyAuditPolicy',
      'policy_type'    => 'Registry Values',
      'policy_value'   => '4,1'
    )
  }
  it {
    should contain_local_security_policy('Audit: Shut down system immediately if unable to log security audits').with(
      'ensure'         => 'present',
      'policy_setting' => 'MACHINE\System\CurrentControlSet\Control\Lsa\CrashOnAuditFail',
      'policy_type'    => 'Registry Values',
      'policy_value'   => '4,0'
    )
  }
  it {
    should contain_local_security_policy('Devices: Allowed to format and eject removable media').with(
      'ensure'         => 'present',
      'policy_setting' => 'MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\AllocateDASD',
      'policy_type'    => 'Registry Values',
      'policy_value'   => '1,"0"'
    )
  }
  it {
    should contain_local_security_policy('Devices: Prevent users from installing printer drivers').with(
      'ensure'         => 'present',
      'policy_setting' => 'MACHINE\System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers\AddPrinterDrivers',
      'policy_type'    => 'Registry Values',
      'policy_value'   => '4,1'
    )
  }
  it {
    should contain_local_security_policy('Domain member: Digitally encrypt or sign secure channel data (always)').with(
      'ensure'         => 'present',
      'policy_setting' => 'MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\RequireSignOrSeal',
      'policy_type'    => 'Registry Values',
      'policy_value'   => '4,1'
    )
  }
  it {
    should contain_local_security_policy('Domain member: Digitally encrypt secure channel data (when possible)').with(
      'ensure'         => 'present',
      'policy_setting' => 'MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\SealSecureChannel',
      'policy_type'    => 'Registry Values',
      'policy_value'   => '4,1'
    )
  }
  it {
    should contain_local_security_policy('Domain member: Digitally sign secure channel data (when possible)').with(
      'ensure'         => 'present',
      'policy_setting' => 'MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\SignSecureChannel',
      'policy_type'    => 'Registry Values',
      'policy_value'   => '4,1'
    )
  }
  it {
    should contain_local_security_policy('Domain member: Disable machine account password changes').with(
      'ensure'         => 'present',
      'policy_setting' => 'MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\DisablePasswordChange',
      'policy_type'    => 'Registry Values',
      'policy_value'   => '4,0'
    )
  }
  it {
    should contain_local_security_policy('Domain member: Maximum machine account password age').with(
      'ensure'         => 'present',
      'policy_setting' => 'MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\MaximumPasswordAge',
      'policy_type'    => 'Registry Values',
      'policy_value'   => '4,30'
    )
  }
  it {
    should contain_local_security_policy('Domain member: Require strong (Windows 2000 or later) session key').with(
      'ensure'         => 'present',
      'policy_setting' => 'MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\RequireStrongKey',
      'policy_type'    => 'Registry Values',
      'policy_value'   => '4,1'
    )
  }
  it {
    should contain_local_security_policy('Interactive logon: Do not display last user name').with(
      'ensure'         => 'present',
      'policy_setting' => 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\DontDisplayLastUserName',
      'policy_type'    => 'Registry Values',
      'policy_value'   => '4,1'
    )
  }
  it {
    should contain_local_security_policy('Interactive logon: Do not require CTRL+ALT+DEL').with(
      'ensure'         => 'present',
      'policy_setting' => 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\DisableCAD',
      'policy_type'    => 'Registry Values',
      'policy_value'   => '4,0'
    )
  }
  it {
    should contain_local_security_policy('Interactive logon: Message text for users attempting to log on').with(
      'ensure'         => 'present',
      'policy_setting' => 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\LegalNoticeText',
      'policy_type'    => 'Registry Values',
      'policy_value'   => '7,Welcome!'
    )
  }
  it {
    should contain_local_security_policy('Interactive logon: Message title for users attempting to log on').with(
      'ensure'         => 'present',
      'policy_setting' => 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\LegalNoticeCaption',
      'policy_type'    => 'Registry Values',
      'policy_value'   => '1,"Title Bar"'
    )
  }
  # L2
  # it {
  #   should contain_local_security_policy('Interactive logon: Number of previous logons to cache (in case domain controller is not available)').with(
  #     'ensure'         => 'present',
  #     'policy_setting' => 'MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\CachedLogonsCount',
  #     'policy_type'    => 'Registry Values',
  #     'policy_value'   => '1,"4"'
  #   )
  # }
  it {
    should contain_local_security_policy('Interactive logon: Prompt user to change password before expiration').with(
      'ensure'         => 'present',
      'policy_setting' => 'MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\PasswordExpiryWarning',
      'policy_type'    => 'Registry Values',
      'policy_value'   => '4,5'
    )
  }
  it {
    should contain_local_security_policy('Interactive logon: Require Domain Controller authentication to unlock workstation').with(
      'ensure'         => 'present',
      'policy_setting' => 'MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\ForceUnlockLogon',
      'policy_type'    => 'Registry Values',
      'policy_value'   => '4,1'
    )
  }
  it {
    should contain_local_security_policy('Interactive logon: Smart card removal behavior').with(
      'ensure'         => 'present',
      'policy_setting' => 'MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\ScRemoveOption',
      'policy_type'    => 'Registry Values',
      'policy_value'   => '1,"1"'
    )
  }
  it {
    should contain_local_security_policy('Microsoft network client: Digitally sign communications (if server agrees)').with(
      'ensure'         => 'present',
      'policy_setting' => 'MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\EnableSecuritySignature',
      'policy_type'    => 'Registry Values',
      'policy_value'   => '4,1'
    )
  }
  it {
    should contain_local_security_policy('Microsoft network client: Send unencrypted password to third-party SMB servers').with(
      'ensure'         => 'present',
      'policy_setting' => 'MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\EnablePlainTextPassword',
      'policy_type'    => 'Registry Values',
      'policy_value'   => '4,0'
    )
  }
  it {
    should contain_local_security_policy('Microsoft network server: Amount of idle time required before suspending session').with(
      'ensure'         => 'present',
      'policy_setting' => 'MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\AutoDisconnect',
      'policy_type'    => 'Registry Values',
      'policy_value'   => '4,15'
    )
  }
  it {
    should contain_local_security_policy('Microsoft network server: Digitally sign communications (always)').with(
      'ensure'         => 'present',
      'policy_setting' => 'MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\RequireSecuritySignature',
      'policy_type'    => 'Registry Values',
      'policy_value'   => '4,1'
    )
  }
  it {
    should contain_local_security_policy('Microsoft network server: Digitally sign communications (if client agrees)').with(
      'ensure'         => 'present',
      'policy_setting' => 'MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\EnableSecuritySignature',
      'policy_type'    => 'Registry Values',
      'policy_value'   => '4,1'
    )
  }
  it {
    should contain_local_security_policy('Microsoft network server: Disconnect clients when logon hours expire').with(
      'ensure'         => 'present',
      'policy_setting' => 'MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\EnableForcedLogOff',
      'policy_type'    => 'Registry Values',
      'policy_value'   => '4,1'
    )
  }
  it {
    should contain_local_security_policy('Network access: Allow anonymous SID/name translation').with(
      'ensure'         => 'present',
      'policy_setting' => 'LSAAnonymousNameLookup',
      'policy_type'    => 'System Access',
      'policy_value'   => '0'
    )
  }
  it {
    should contain_local_security_policy('Network access: Do not allow anonymous enumeration of SAM accounts').with(
      'ensure'         => 'present',
      'policy_setting' => 'MACHINE\System\CurrentControlSet\Control\Lsa\RestrictAnonymousSAM',
      'policy_type'    => 'Registry Values',
      'policy_value'   => '4,1'
    )
  }
  it {
    should contain_local_security_policy('Network access: Do not allow anonymous enumeration of SAM accounts and shares').with(
      'ensure'         => 'present',
      'policy_setting' => 'MACHINE\System\CurrentControlSet\Control\Lsa\RestrictAnonymous',
      'policy_type'    => 'Registry Values',
      'policy_value'   => '4,1'
    )
  }
  # L2
  # it {
  #   should contain_local_security_policy('Network access: Do not allow storage of passwords and credentials for network authentication').with(
  #     'ensure'         => 'present',
  #     'policy_setting' => 'MACHINE\System\CurrentControlSet\Control\Lsa\DisableDomainCreds',
  #     'policy_type'    => 'Registry Values',
  #     'policy_value'   => '4,0'
  #   )
  # }
  it {
    should contain_local_security_policy('Network access: Let Everyone permissions apply to anonymous users').with(
      'ensure'         => 'present',
      'policy_setting' => 'MACHINE\System\CurrentControlSet\Control\Lsa\EveryoneIncludesAnonymous',
      'policy_type'    => 'Registry Values',
      'policy_value'   => '4,0'
    )
  }
  it {
    should contain_local_security_policy('Network access: Remotely accessible registry paths').with(
      'ensure'         => 'present',
      'policy_setting' => 'MACHINE\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths\Machine',
      'policy_type'    => 'Registry Values',
      'policy_value'   => '7,System\CurrentControlSet\Control\ProductOptions,System\CurrentControlSet\Control\Server Applications,Software\Microsoft\Windows NT\CurrentVersion'
    )
  }
  it {
    should contain_local_security_policy('Network access: Remotely accessible registry paths and sub-paths').with(
      'ensure'         => 'present',
      'policy_setting' => 'MACHINE\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths\Machine',
      'policy_type'    => 'Registry Values',
      'policy_value'   => '7,System\CurrentControlSet\Control\Print\Printers,System\CurrentControlSet\Services\Eventlog,Software\Microsoft\OLAP Server,Software\Microsoft\Windows NT\CurrentVersion\Print,Software\Microsoft\Windows NT\CurrentVersion\Windows,System\CurrentControlSet\Control\ContentIndex,System\CurrentControlSet\Control\Terminal Server,System\CurrentControlSet\Control\Terminal Server\UserConfig,System\CurrentControlSet\Control\Terminal Server\DefaultUserConfiguration,Software\Microsoft\Windows NT\CurrentVersion\Perflib,System\CurrentControlSet\Services\SysmonLog'
    )
  }
  it {
    should contain_local_security_policy('Network access: Restrict anonymous access to Named Pipes and Shares').with(
      'ensure'         => 'present',
      'policy_setting' => 'MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\RestrictNullSessAccess',
      'policy_type'    => 'Registry Values',
      'policy_value'   => '4,1'
    )
  }
  it {
    should contain_local_security_policy('Network access: Sharing and security model for local accounts').with(
      'ensure'         => 'present',
      'policy_setting' => 'MACHINE\System\CurrentControlSet\Control\Lsa\ForceGuest',
      'policy_type'    => 'Registry Values',
      'policy_value'   => '4,0'
    )
  }
  it {
    should contain_local_security_policy('Network security: All Local System to use computer identity for NTLM').with(
      'ensure'         => 'present',
      'policy_setting' => 'MACHINE\System\CurrentControlSet\Control\Lsa\UseMachineId',
      'policy_type'    => 'Registry Values',
      'policy_value'   => '4,1'
    )
  }
  it {
    should contain_local_security_policy('Network security: Force logoff when logon hours expire').with(
      'ensure'         => 'present',
      'policy_setting' => 'ForceLogoffWhenHourExpire',
      'policy_type'    => 'System Access',
      'policy_value'   => '1'
    )
  }
  it {
    should contain_local_security_policy('Network security: LAN Manager authentication level').with(
      'ensure'         => 'present',
      'policy_setting' => 'MACHINE\System\CurrentControlSet\Control\Lsa\LmCompatibilityLevel',
      'policy_type'    => 'Registry Values',
      'policy_value'   => '4,5'
    )
  }
  it {
    should contain_local_security_policy('Network security: LDAP client signing requirements').with(
      'ensure'         => 'present',
      'policy_setting' => 'MACHINE\System\CurrentControlSet\Services\LDAP\LDAPClientIntegrity',
      'policy_type'    => 'Registry Values',
      'policy_value'   => '4,1'
    )
  }
  it {
    should contain_local_security_policy('Network security: Minimum session security for NTLM SSP based (including secure RPC) clients').with(
      'ensure'         => 'present',
      'policy_setting' => 'MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\NTLMMinClientSec',
      'policy_type'    => 'Registry Values',
      'policy_value'   => '4,537395200'
    )
  }
  it {
    should contain_local_security_policy('Network security: Minimum session security for NTLM SSP based (including secure RPC) servers').with(
      'ensure'         => 'present',
      'policy_setting' => 'MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\NTLMMinServerSec',
      'policy_type'    => 'Registry Values',
      'policy_value'   => '4,537395200'
    )
  }
  it {
    should contain_local_security_policy('Shutdown: Allow system to be shut down without having to log on').with(
      'ensure'         => 'present',
      'policy_setting' => 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ShutdownWithoutLogon',
      'policy_type'    => 'Registry Values',
      'policy_value'   => '4,0'
    )
  }
  it {
    should contain_local_security_policy('System objects: Require case insensitivity for non-Windows subsystems').with(
      'ensure'         => 'present',
      'policy_setting' => 'MACHINE\System\CurrentControlSet\Control\Session Manager\Kernel\ObCaseInsensitive',
      'policy_type'    => 'Registry Values',
      'policy_value'   => '4,1'
    )
  }
  it {
    should contain_local_security_policy('System objects: Strengthen default permissions of internal system objects (e.g., Symbolic Links)').with(
      'ensure'         => 'present',
      'policy_setting' => 'MACHINE\System\CurrentControlSet\Control\Session Manager\ProtectionMode',
      'policy_type'    => 'Registry Values',
      'policy_value'   => '4,1'
    )
  }
  it {
    should contain_local_security_policy('System settings: Optional subsystems').with(
      'ensure'         => 'present',
      'policy_setting' => 'MACHINE\System\CurrentControlSet\Control\Session Manager\SubSystems\optional',
      'policy_type'    => 'Registry Values',
      'policy_value'   => '7,Defined: (blank)'
    )
  }
  it {
    should contain_local_security_policy('User Account Control: Admin Approval Mode for the Built-in Administrator account').with(
      'ensure'         => 'present',
      'policy_setting' => 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken',
      'policy_type'    => 'Registry Values',
      'policy_value'   => '4,1'
    )
  }
  it {
    should contain_local_security_policy('User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop').with(
      'ensure'         => 'present',
      'policy_setting' => 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle',
      'policy_type'    => 'Registry Values',
      'policy_value'   => '4,0'
    )
  }
  it {
    should contain_local_security_policy('User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode').with(
      'ensure'         => 'present',
      'policy_setting' => 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin',
      'policy_type'    => 'Registry Values',
      'policy_value'   => '4,2'
    )
  }
  it {
    should contain_local_security_policy('User Account Control: Behavior of the elevation prompt for standard users').with(
      'ensure'         => 'present',
      'policy_setting' => 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser',
      'policy_type'    => 'Registry Values',
      'policy_value'   => '4,0'
    )
  }
  it {
    should contain_local_security_policy('User Account Control: Detect application installations and prompt for elevation').with(
      'ensure'         => 'present',
      'policy_setting' => 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection',
      'policy_type'    => 'Registry Values',
      'policy_value'   => '4,1'
    )
  }
  it {
    should contain_local_security_policy('User Account Control: Only elevate UIAccess applications that are installed in secure locations').with(
      'ensure'         => 'present',
      'policy_setting' => 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths',
      'policy_type'    => 'Registry Values',
      'policy_value'   => '4,1'
    )
  }
  it {
    should contain_local_security_policy('User Account Control: Run all administrators in Admin Approval Mode').with(
      'ensure'         => 'present',
      'policy_setting' => 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA',
      'policy_type'    => 'Registry Values',
      'policy_value'   => '4,1'
    )
  }
  it {
    should contain_local_security_policy('User Account Control: Switch to the secure desktop when prompting for elevation').with(
      'ensure'         => 'present',
      'policy_setting' => 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop',
      'policy_type'    => 'Registry Values',
      'policy_value'   => '4,1'
    )
  }
  it {
    should contain_local_security_policy('User Account Control: Virtualize file and registry write failures to per-user locations').with(
      'ensure'         => 'present',
      'policy_setting' => 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization',
      'policy_type'    => 'Registry Values',
      'policy_value'   => '4,1'
    )
  }
  it {
    should contain_registry__value('DomainEnableFirewall').with(
      'key' => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile',
      'value' => 'EnableFirewall',
      'type'  => 'dword',
      'data'  => '0x00000001'
    )
  }

end
