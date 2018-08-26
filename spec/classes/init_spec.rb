require 'spec_helper'
describe 'harden_windows_server' do
  context 'Member Server Level 1' do
    let(:facts) { { 'operatingsystem' => 'windows' } }
    # it { is_expected.to compile }
    let(:params) { { 'is_domain_controller' => false } }

    it {
      is_expected.to contain_class('Harden_windows_server::Configure') {}
    }
    it {
      is_expected.to contain_local_security_policy('Enforce password history').with(
        'ensure' => 'present',
        'policy_setting' => 'PasswordHistorySize',
        'policy_type' => 'System Access',
        'policy_value' => '24',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Maximum password age').with(
        'ensure'         => 'present',
        'policy_setting' => 'MaximumPasswordAge',
        'policy_type'    => 'System Access',
        'policy_value'   => '42',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Minimum password age').with(
        'ensure'         => 'present',
        'policy_setting' => 'MinimumPasswordAge',
        'policy_type'    => 'System Access',
        'policy_value'   => '1',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Minimum password length').with(
        'ensure'         => 'present',
        'policy_setting' => 'MinimumPasswordLength',
        'policy_type'    => 'System Access',
        'policy_value'   => '14',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Password must meet complexity requirements').with(
        'ensure'         => 'present',
        'policy_setting' => 'PasswordComplexity',
        'policy_type'    => 'System Access',
        'policy_value'   => 'enabled',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Store passwords using reversible encryption').with(
        'ensure'         => 'present',
        'policy_setting' => 'ClearTextPassword',
        'policy_type'    => 'System Access',
        'policy_value'   => 'disabled',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Account lockout duration').with(
        'ensure'         => 'present',
        'policy_setting' => 'LockoutDuration',
        'policy_type'    => 'System Access',
        'policy_value'   => '30',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Account lockout threshold').with(
        'ensure'         => 'present',
        'policy_setting' => 'LockoutBadCount',
        'policy_type'    => 'System Access',
        'policy_value'   => '10',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Reset account lockout counter after').with(
        'ensure'         => 'present',
        'policy_setting' => 'ResetLockoutCount',
        'policy_type'    => 'System Access',
        'policy_value'   => '30',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Access Credential Manager as a trusted caller').with(
        'ensure'         => 'absent',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Access this computer from the network').with(
        'ensure'         => 'present',
        'policy_setting' => 'SeNetworkLogonRight',
        'policy_type'    => 'Privilege Rights',
        'policy_value'   => 'set: Administrators, Authenticated Users',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Act as part of the operating system').with(
        'ensure'         => 'absent',
      )
    }
    # it {
    #   should contain_local_security_policy('Add workstations to domain').with(
    #     'ensure'         => 'absent'
    #   )
    # }
    it {
      is_expected.to contain_local_security_policy('Adjust memory quotas for a process').with(
        'ensure'         => 'present',
        'policy_setting' => 'SeIncreaseQuotaPrivilege',
        'policy_type'    => 'Privilege Rights',
        'policy_value'   => 'set: Local Service, Network Service, Administrators',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Allow log on locally').with(
        'ensure'         => 'present',
        'policy_setting' => 'SeInteractiveLogonRight',
        'policy_type'    => 'Privilege Rights',
        'policy_value'   => 'set: Administrators',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Allow log on through Remote Desktop Services').with(
        'ensure'         => 'present',
        'policy_setting' => 'SeRemoteInteractiveLogonRight',
        'policy_type'    => 'Privilege Rights',
        'policy_value'   => 'set: Administrators, Remote Desktop Users',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Back up files and directories').with(
        'ensure'         => 'present',
        'policy_setting' => 'SeBackupPrivilege',
        'policy_type'    => 'Privilege Rights',
        'policy_value'   => 'set: Administrators',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Change the system time').with(
        'ensure'         => 'present',
        'policy_setting' => 'SeSystemtimePrivilege',
        'policy_type'    => 'Privilege Rights',
        'policy_value'   => 'set: Local Service, Administrators',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Change the time zone').with(
        'ensure'         => 'present',
        'policy_setting' => 'SeTimeZonePrivilege',
        'policy_type'    => 'Privilege Rights',
        'policy_value'   => 'set: Local Service, Administrators',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Create a pagefile').with(
        'ensure'         => 'present',
        'policy_setting' => 'SeCreatePagefilePrivilege',
        'policy_type'    => 'Privilege Rights',
        'policy_value'   => 'set: Administrators',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Create a token object').with(
        'ensure'         => 'absent',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Create global objects').with(
        'ensure'         => 'present',
        'policy_setting' => 'SeCreateGlobalPrivilege',
        'policy_type'    => 'Privilege Rights',
        'policy_value'   => 'set: Local Service, Network Service, Administrators, Service',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Create permanent shared objects').with(
        'ensure'         => 'absent',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Create symbolic links').with(
        'ensure'         => 'present',
        'policy_setting' => 'SeCreateSymbolicLinkPrivilege',
        'policy_type'    => 'Privilege Rights',
# FIXME! only if Hyper-V role
#        'policy_value'   => 'set: Administrators, Virtual Machines',
        'policy_value'   => 'set: Administrators',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Debug programs').with(
        'ensure'         => 'present',
        'policy_setting' => 'SeDebugPrivilege',
        'policy_type'    => 'Privilege Rights',
        'policy_value'   => 'set: Administrators',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Deny access to this computer from the network').with(
        'ensure'         => 'present',
        'policy_setting' => 'SeDenyNetworkLogonRight',
        'policy_type'    => 'Privilege Rights',
        'policy_value'   => 'set: Guests, Local, Administrators',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Deny log on as a batch job').with(
        'ensure'         => 'present',
        'policy_setting' => 'SeDenyBatchLogonRight',
        'policy_type'    => 'Privilege Rights',
        'policy_value'   => 'set: Guests',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Deny log on as a service').with(
        'ensure'         => 'present',
        'policy_setting' => 'SeDenyServiceLogonRight',
        'policy_type'    => 'Privilege Rights',
        'policy_value'   => 'set: Guests',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Deny log on locally').with(
        'ensure'         => 'present',
        'policy_setting' => 'SeDenyInteractiveLogonRight',
        'policy_type'    => 'Privilege Rights',
        'policy_value'   => 'set: Guests',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Deny log on through Remote Desktop Services').with(
        'ensure'         => 'present',
        'policy_setting' => 'SeDenyRemoteInteractiveLogonRight',
        'policy_type'    => 'Privilege Rights',
        'policy_value'   => 'set: Guests, Local',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Enable computer and user accounts to be trusted for delegation').with(
        'ensure'         => 'absent',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Force shutdown from a remote system').with(
        'ensure'         => 'present',
        'policy_setting' => 'SeRemoteShutdownPrivilege',
        'policy_type'    => 'Privilege Rights',
        'policy_value'   => 'set: Administrators',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Generate security audits').with(
        'ensure'         => 'present',
        'policy_setting' => 'SeAuditPrivilege',
        'policy_type'    => 'Privilege Rights',
        'policy_value'   => 'set: Local Service, Network Service',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Impersonate a client after authentication').with(
        'ensure'         => 'present',
        'policy_setting' => 'SeImpersonatePrivilege',
        'policy_type'    => 'Privilege Rights',
        'policy_value'   => 'set: Local Service, Network Service, Administrators, Service',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Increase scheduling priority').with(
        'ensure'         => 'present',
        'policy_setting' => 'SeIncreaseBasePriorityPrivilege',
        'policy_type'    => 'Privilege Rights',
        'policy_value'   => 'set: Administrators',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Load and unload device drivers').with(
        'ensure'         => 'present',
        'policy_setting' => 'SeLoadDriverPrivilege',
        'policy_type'    => 'Privilege Rights',
        'policy_value'   => 'set: Administrators',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Lock pages in memory').with(
        'ensure'         => 'absent',
      )
    }
    # it {
    #   should contain_local_security_policy('Log on as a batch job').with(
    #     'ensure'         => 'absent'
    #   )
    # }
    it {
      is_expected.to contain_local_security_policy('Manage auditing and security log').with(
        'ensure'         => 'present',
        'policy_setting' => 'SeSecurityPrivilege',
        'policy_type'    => 'Privilege Rights',
        'policy_value'   => 'set: Administrators',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Modify an object label').with(
        'ensure'         => 'absent',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Modify firmware environment values').with(
        'ensure'         => 'present',
        'policy_setting' => 'SeSystemEnvironmentPrivilege',
        'policy_type'    => 'Privilege Rights',
        'policy_value'   => 'set: Administrators',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Perform volume maintenance tasks').with(
        'ensure'         => 'present',
        'policy_setting' => 'SeManageVolumePrivilege',
        'policy_type'    => 'Privilege Rights',
        'policy_value'   => 'set: Administrators',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Profile single process').with(
        'ensure'         => 'present',
        'policy_setting' => 'SeProfileSingleProcessPrivilege',
        'policy_type'    => 'Privilege Rights',
        'policy_value'   => 'set: Administrators',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Profile system performance').with(
        'ensure'         => 'present',
        'policy_setting' => 'SeSystemProfilePrivilege',
        'policy_type'    => 'Privilege Rights',
        'policy_value'   => 'set: Administrators, NT SERVICE\WdiServiceHost',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Replace a process level token').with(
        'ensure'         => 'present',
        'policy_setting' => 'SeAssignPrimaryTokenPrivilege',
        'policy_type'    => 'Privilege Rights',
        'policy_value'   => 'set: Local Service, Network Service',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Restore files and directories').with(
        'ensure'         => 'present',
        'policy_setting' => 'SeRestorePrivilege',
        'policy_type'    => 'Privilege Rights',
        'policy_value'   => 'set: Administrators',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Shut down the system').with(
        'ensure'         => 'present',
        'policy_setting' => 'SeShutdownPrivilege',
        'policy_type'    => 'Privilege Rights',
        'policy_value'   => 'set: Administrators',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Take ownership of files or other objects').with(
        'ensure'         => 'present',
        'policy_setting' => 'SeTakeOwnershipPrivilege',
        'policy_type'    => 'Privilege Rights',
        'policy_value'   => 'set: Administrators',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Accounts: Limit local account use of blank passwords to console logon only').with(
        'ensure'         => 'present',
        'policy_setting' => 'MACHINE\System\CurrentControlSet\Control\Lsa\LimitBlankPasswordUse',
        'policy_type'    => 'Registry Values',
        'policy_value'   => 'enabled',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Accounts: Rename administrator account').with(
        'ensure'         => 'present',
        'policy_setting' => 'NewAdministratorName',
        'policy_type'    => 'System Access',
        'policy_value'   => '"adminaccount"',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Accounts: Rename guest account').with(
        'ensure'         => 'present',
        'policy_setting' => 'NewGuestName',
        'policy_type'    => 'System Access',
        'policy_value'   => '"guestaccount"',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings').with(
        'ensure'         => 'present',
        'policy_setting' => 'MACHINE\System\CurrentControlSet\Control\Lsa\SCENoApplyLegacyAuditPolicy',
        'policy_type'    => 'Registry Values',
        'policy_value'   => 'enabled',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Audit: Shut down system immediately if unable to log security audits').with(
        'ensure'         => 'present',
        'policy_setting' => 'MACHINE\System\CurrentControlSet\Control\Lsa\CrashOnAuditFail',
        'policy_type'    => 'Registry Values',
        'policy_value'   => 'disabled',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Devices: Allowed to format and eject removable media').with(
        'ensure'         => 'present',
        'policy_setting' => 'MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\AllocateDASD',
        'policy_type'    => 'Registry Values',
        'policy_value'   => 'Administrators',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Devices: Prevent users from installing printer drivers').with(
        'ensure'         => 'present',
        'policy_setting' => 'MACHINE\System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers\AddPrinterDrivers',
        'policy_type'    => 'Registry Values',
        'policy_value'   => 'enabled',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Domain member: Digitally encrypt or sign secure channel data (always)').with(
        'ensure'         => 'present',
        'policy_setting' => 'MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\RequireSignOrSeal',
        'policy_type'    => 'Registry Values',
        'policy_value'   => 'enabled',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Domain member: Digitally encrypt secure channel data (when possible)').with(
        'ensure'         => 'present',
        'policy_setting' => 'MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\SealSecureChannel',
        'policy_type'    => 'Registry Values',
        'policy_value'   => 'enabled',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Domain member: Digitally sign secure channel data (when possible)').with(
        'ensure'         => 'present',
        'policy_setting' => 'MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\SignSecureChannel',
        'policy_type'    => 'Registry Values',
        'policy_value'   => 'enabled',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Domain member: Disable machine account password changes').with(
        'ensure'         => 'present',
        'policy_setting' => 'MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\DisablePasswordChange',
        'policy_type'    => 'Registry Values',
        'policy_value'   => 'disabled',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Domain member: Maximum machine account password age').with(
        'ensure'         => 'present',
        'policy_setting' => 'MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\MaximumPasswordAge',
        'policy_type'    => 'Registry Values',
        'policy_value'   => '4,30',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Domain member: Require strong (Windows 2000 or later) session key').with(
        'ensure'         => 'present',
        'policy_setting' => 'MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\RequireStrongKey',
        'policy_type'    => 'Registry Values',
        'policy_value'   => 'enabled',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Interactive logon: Do not display last user name').with(
        'ensure'         => 'present',
        'policy_setting' => 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\DontDisplayLastUserName',
        'policy_type'    => 'Registry Values',
        'policy_value'   => 'enabled',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Interactive logon: Do not require CTRL+ALT+DEL').with(
        'ensure'         => 'present',
        'policy_setting' => 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\DisableCAD',
        'policy_type'    => 'Registry Values',
        'policy_value'   => 'disabled',
      )
    }
    # it {
    #   should contain_local_security_policy('Interactive logon: Message text for users attempting to log on').with(
    #     'ensure'         => 'present',
    #     'policy_setting' => 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\LegalNoticeText',
    #     'policy_type'    => 'Registry Values',
    #     'policy_value'   => '7,Welcome!'
    #   )
    # }
    # it {
    #   should contain_local_security_policy('Interactive logon: Message title for users attempting to log on').with(
    #     'ensure'         => 'present',
    #     'policy_setting' => 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\LegalNoticeCaption',
    #     'policy_type'    => 'Registry Values',
    #     'policy_value'   => '1,"Title Bar"'
    #   )
    # }
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
      is_expected.to contain_local_security_policy('Interactive logon: Prompt user to change password before expiration').with(
        'ensure'         => 'present',
        'policy_setting' => 'MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\PasswordExpiryWarning',
        'policy_type'    => 'Registry Values',
        'policy_value'   => '4,5',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Interactive logon: Require Domain Controller authentication to unlock workstation').with(
        'ensure'         => 'present',
        'policy_setting' => 'MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\ForceUnlockLogon',
        'policy_type'    => 'Registry Values',
        'policy_value'   => 'enabled',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Interactive logon: Smart card removal behavior').with(
        'ensure'         => 'present',
        'policy_setting' => 'MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\ScRemoveOption',
        'policy_type'    => 'Registry Values',
        'policy_value'   => 'Lock Workstation',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Microsoft network client: Digitally sign communications (always)').with(
        'ensure'         => 'present',
        'policy_setting' => 'MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\RequireSecuritySignature',
        'policy_type'    => 'Registry Values',
        'policy_value'   => 'enabled',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Microsoft network client: Digitally sign communications (if server agrees)').with(
        'ensure'         => 'present',
        'policy_setting' => 'MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\EnableSecuritySignature',
        'policy_type'    => 'Registry Values',
        'policy_value'   => 'enabled',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Microsoft network client: Send unencrypted password to third-party SMB servers').with(
        'ensure'         => 'present',
        'policy_setting' => 'MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\EnablePlainTextPassword',
        'policy_type'    => 'Registry Values',
        'policy_value'   => 'disabled',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Microsoft network server: Amount of idle time required before suspending session').with(
        'ensure'         => 'present',
        'policy_setting' => 'MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\AutoDisconnect',
        'policy_type'    => 'Registry Values',
        'policy_value'   => '4,15',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Microsoft network server: Digitally sign communications (always)').with(
        'ensure'         => 'present',
        'policy_setting' => 'MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\RequireSecuritySignature',
        'policy_type'    => 'Registry Values',
        'policy_value'   => 'enabled',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Microsoft network server: Digitally sign communications (if client agrees)').with(
        'ensure'         => 'present',
        'policy_setting' => 'MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\EnableSecuritySignature',
        'policy_type'    => 'Registry Values',
        'policy_value'   => 'enabled',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Microsoft network server: Disconnect clients when logon hours expire').with(
        'ensure'         => 'present',
        'policy_setting' => 'MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\EnableForcedLogOff',
        'policy_type'    => 'Registry Values',
        'policy_value'   => 'enabled',
      )
    }
    it {
      is_expected.to contain_registry__value('SmbServerNameHardeningLevel').with(
        'key'   => 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters',
        'value' => 'SmbServerNameHardeningLevel',
        'type'  => 'dword',
        'data'  => '0x00000001',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Network access: Allow anonymous SID/name translation').with(
        'ensure'         => 'present',
        'policy_setting' => 'LSAAnonymousNameLookup',
        'policy_type'    => 'System Access',
        'policy_value'   => 'disabled',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Network access: Do not allow anonymous enumeration of SAM accounts').with(
        'ensure'         => 'present',
        'policy_setting' => 'MACHINE\System\CurrentControlSet\Control\Lsa\RestrictAnonymousSAM',
        'policy_type'    => 'Registry Values',
        'policy_value'   => 'enabled',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Network access: Do not allow anonymous enumeration of SAM accounts and shares').with(
        'ensure'         => 'present',
        'policy_setting' => 'MACHINE\System\CurrentControlSet\Control\Lsa\RestrictAnonymous',
        'policy_type'    => 'Registry Values',
        'policy_value'   => 'enabled',
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
      is_expected.to contain_local_security_policy('Network access: Let Everyone permissions apply to anonymous users').with(
        'ensure'         => 'present',
        'policy_setting' => 'MACHINE\System\CurrentControlSet\Control\Lsa\EveryoneIncludesAnonymous',
        'policy_type'    => 'Registry Values',
        'policy_value'   => 'disabled',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Network access: Remotely accessible registry paths').with(
        'ensure'         => 'present',
        'policy_setting' => 'MACHINE\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths\Machine',
        'policy_type'    => 'Registry Values',
        'policy_value'   => '7,System\CurrentControlSet\Control\ProductOptions,System\CurrentControlSet\Control\Server Applications,Software\Microsoft\Windows NT\CurrentVersion',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Network access: Remotely accessible registry paths and sub-paths').with(
        'ensure'         => 'present',
        'policy_setting' => 'MACHINE\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths\Machine',
        'policy_type'    => 'Registry Values',
        'policy_value'   => '7,System\CurrentControlSet\Control\Print\Printers,System\CurrentControlSet\Services\Eventlog,' \
                            'Software\Microsoft\OLAP Server,Software\Microsoft\Windows NT\CurrentVersion\Print,' \
                            'Software\Microsoft\Windows NT\CurrentVersion\Windows,System\CurrentControlSet\Control\ContentIndex,' \
                            'System\CurrentControlSet\Control\Terminal Server,' \
                            'System\CurrentControlSet\Control\Terminal Server\UserConfig,' \
                            'System\CurrentControlSet\Control\Terminal Server\DefaultUserConfiguration,' \
                            'Software\Microsoft\Windows NT\CurrentVersion\Perflib,System\CurrentControlSet\Services\SysmonLog',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Network access: Restrict anonymous access to Named Pipes and Shares').with(
        'ensure'         => 'present',
        'policy_setting' => 'MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\RestrictNullSessAccess',
        'policy_type'    => 'Registry Values',
        'policy_value'   => 'enabled',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Network access: Sharing and security model for local accounts').with(
        'ensure'         => 'present',
        'policy_setting' => 'MACHINE\System\CurrentControlSet\Control\Lsa\ForceGuest',
        'policy_type'    => 'Registry Values',
        'policy_value'   => 'Classic - local users authenticate as themselves',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Network security: All Local System to use computer identity for NTLM').with(
        'ensure'         => 'present',
        'policy_setting' => 'MACHINE\System\CurrentControlSet\Control\Lsa\UseMachineId',
        'policy_type'    => 'Registry Values',
        'policy_value'   => 'enabled',
      )
    }
    it {
      is_expected.to contain_registry__value('allownullsessionfallback').with(
        'key'   => 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0',
        'value' => 'allownullsessionfallback',
        'type'  => 'dword',
        'data'  => '0x00000000',
      )
    }
    it {
      is_expected.to contain_registry__value('AllowOnlineID').with(
        'key'   => 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\pku2u',
        'value' => 'AllowOnlineID',
        'type'  => 'dword',
        'data'  => '0x00000000',
      )
    }
    it {
      is_expected.to contain_registry__value('SupportedEncryptionTypes').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters',
        'value' => 'SupportedEncryptionTypes',
        'type'  => 'dword',
        'data'  => '0x7ffffffc',
      )
    }
    it {
      is_expected.to contain_registry__value('NoLmHash').with(
        'key'   => 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa',
        'value' => 'NoLmHash',
        'type'  => 'dword',
        'data'  => '0x00000001',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Network security: Force logoff when logon hours expire').with(
        'ensure'         => 'present',
        'policy_setting' => 'ForceLogoffWhenHourExpire',
        'policy_type'    => 'System Access',
        'policy_value'   => '1',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Network security: LAN Manager authentication level').with(
        'ensure'         => 'present',
        'policy_setting' => 'MACHINE\System\CurrentControlSet\Control\Lsa\LmCompatibilityLevel',
        'policy_type'    => 'Registry Values',
        'policy_value'   => '4,5',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Network security: LDAP client signing requirements').with(
        'ensure'         => 'present',
        'policy_setting' => 'MACHINE\System\CurrentControlSet\Services\LDAP\LDAPClientIntegrity',
        'policy_type'    => 'Registry Values',
        'policy_value'   => 'enabled',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Network security: Minimum session security for NTLM SSP based (including secure RPC) clients').with(
        'ensure'         => 'present',
        'policy_setting' => 'MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\NTLMMinClientSec',
        'policy_type'    => 'Registry Values',
        'policy_value'   => '4,537395200',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Network security: Minimum session security for NTLM SSP based (including secure RPC) servers').with(
        'ensure'         => 'present',
        'policy_setting' => 'MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\NTLMMinServerSec',
        'policy_type'    => 'Registry Values',
        'policy_value'   => '4,537395200',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Shutdown: Allow system to be shut down without having to log on').with(
        'ensure'         => 'present',
        'policy_setting' => 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ShutdownWithoutLogon',
        'policy_type'    => 'Registry Values',
        'policy_value'   => 'disabled',
      )
    }
    it {
      is_expected.to contain_local_security_policy('System objects: Require case insensitivity for non-Windows subsystems').with(
        'ensure'         => 'present',
        'policy_setting' => 'MACHINE\System\CurrentControlSet\Control\Session Manager\Kernel\ObCaseInsensitive',
        'policy_type'    => 'Registry Values',
        'policy_value'   => 'enabled',
      )
    }
    it {
      is_expected.to contain_local_security_policy('System objects: Strengthen default permissions of internal system objects (e.g., Symbolic Links)').with(
        'ensure'         => 'present',
        'policy_setting' => 'MACHINE\System\CurrentControlSet\Control\Session Manager\ProtectionMode',
        'policy_type'    => 'Registry Values',
        'policy_value'   => 'enabled',
      )
    }
    it {
      is_expected.to contain_local_security_policy('System settings: Optional subsystems').with(
        'ensure'         => 'present',
        'policy_setting' => 'MACHINE\System\CurrentControlSet\Control\Session Manager\SubSystems\optional',
        'policy_type'    => 'Registry Values',
        'policy_value'   => '7,Defined: (blank)',
      )
    }
    it {
      is_expected.to contain_local_security_policy('User Account Control: Admin Approval Mode for the Built-in Administrator account').with(
        'ensure'         => 'present',
        'policy_setting' => 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken',
        'policy_type'    => 'Registry Values',
        'policy_value'   => 'enabled',
      )
    }
    it {
      is_expected.to contain_local_security_policy('User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop').with(
        'ensure'         => 'present',
        'policy_setting' => 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle',
        'policy_type'    => 'Registry Values',
        'policy_value'   => 'disabled',
      )
    }
    it {
      is_expected.to contain_local_security_policy('User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode').with(
        'ensure'         => 'present',
        'policy_setting' => 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin',
        'policy_type'    => 'Registry Values',
        'policy_value'   => '4,2',
      )
    }
    it {
      is_expected.to contain_local_security_policy('User Account Control: Behavior of the elevation prompt for standard users').with(
        'ensure'         => 'present',
        'policy_setting' => 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser',
        'policy_type'    => 'Registry Values',
        'policy_value'   => 'disabled',
      )
    }
    it {
      is_expected.to contain_local_security_policy('User Account Control: Detect application installations and prompt for elevation').with(
        'ensure'         => 'present',
        'policy_setting' => 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection',
        'policy_type'    => 'Registry Values',
        'policy_value'   => 'enabled',
      )
    }
    it {
      is_expected.to contain_local_security_policy('User Account Control: Only elevate UIAccess applications that are installed in secure locations').with(
        'ensure'         => 'present',
        'policy_setting' => 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths',
        'policy_type'    => 'Registry Values',
        'policy_value'   => 'enabled',
      )
    }
    it {
      is_expected.to contain_local_security_policy('User Account Control: Run all administrators in Admin Approval Mode').with(
        'ensure'         => 'present',
        'policy_setting' => 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA',
        'policy_type'    => 'Registry Values',
        'policy_value'   => 'enabled',
      )
    }
    it {
      is_expected.to contain_local_security_policy('User Account Control: Switch to the secure desktop when prompting for elevation').with(
        'ensure'         => 'present',
        'policy_setting' => 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop',
        'policy_type'    => 'Registry Values',
        'policy_value'   => 'enabled',
      )
    }
    it {
      is_expected.to contain_local_security_policy('User Account Control: Virtualize file and registry write failures to per-user locations').with(
        'ensure'         => 'present',
        'policy_setting' => 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization',
        'policy_type'    => 'Registry Values',
        'policy_value'   => 'enabled',
      )
    }
    it {
      is_expected.to contain_registry__value('DomainEnableFirewall').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile',
        'value' => 'EnableFirewall',
        'type'  => 'dword',
        'data'  => '0x00000001',
      )
    }
    it {
      is_expected.to contain_registry__value('DomainDefaultInboundAction').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile',
        'value' => 'DefaultInboundAction',
        'type'  => 'dword',
        'data'  => '0x00000001',
      )
    }
    it {
      is_expected.to contain_registry__value('DomainDefaultOutboundAction').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile',
        'value' => 'DefaultOutboundAction',
        'type'  => 'dword',
        'data'  => '0x00000000',
      )
    }
    it {
      is_expected.to contain_registry__value('DomainbDisableNotifications').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile',
        'value' => 'DisableNotifications',
        'type'  => 'dword',
        'data'  => '0x00000001',
      )
    }
    it {
      is_expected.to contain_registry__value('DomainAllowLocalPolicyMerge').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile',
        'value' => 'AllowLocalPolicyMerge',
        'type'  => 'dword',
        'data'  => '0x00000001',
      )
    }
    it {
      is_expected.to contain_registry__value('DomainAllowLocalIPsecPolicyMerge').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile',
        'value' => 'AllowLocalIPsecPolicyMerge',
        'type'  => 'dword',
        'data'  => '0x00000001',
      )
    }
    it {
      is_expected.to contain_registry__value('DomainLogFilePath').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging',
        'value' => 'LogFilePath',
        'type'  => 'string',
        'data'  => '%systemroot%\system32\logfiles\firewall\domainfw.log',
      )
    }
    it {
      is_expected.to contain_registry__value('DomainLogFileSize').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging',
        'value' => 'LogFileSize',
        'type'  => 'dword',
        'data'  => '0x00004000',
      )
    }
    it {
      is_expected.to contain_registry__value('DomainLogDroppedPackets').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging',
        'value' => 'LogDroppedPackets',
        'type'  => 'dword',
        'data'  => '0x00000001',
      )
    }
    it {
      is_expected.to contain_registry__value('DomainLogSuccessfulConnections').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging',
        'value' => 'LogSuccessfulConnections',
        'type'  => 'dword',
        'data'  => '0x00000001',
      )
    }
    it {
      is_expected.to contain_registry__value('PrivateEnableFirewall').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile',
        'value' => 'EnableFirewall',
        'type'  => 'dword',
        'data'  => '0x00000001',
      )
    }
    it {
      is_expected.to contain_registry__value('PrivateDefaultInboundAction').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile',
        'value' => 'DefaultInboundAction',
        'type'  => 'dword',
        'data'  => '0x00000001',
      )
    }
    it {
      is_expected.to contain_registry__value('PrivateDefaultOutboundAction').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile',
        'value' => 'DefaultOutboundAction',
        'type'  => 'dword',
        'data'  => '0x00000000',
      )
    }
    it {
      is_expected.to contain_registry__value('PrivateDisableNotifications').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile',
        'value' => 'DisableNotifications',
        'type'  => 'dword',
        'data'  => '0x00000001',
      )
    }
    it {
      is_expected.to contain_registry__value('PrivateAllowLocalPolicyMerge').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile',
        'value' => 'AllowLocalPolicyMerge',
        'type'  => 'dword',
        'data'  => '0x00000001',
      )
    }
    it {
      is_expected.to contain_registry__value('PrivateAllowLocalIPsecPolicyMerge').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile',
        'value' => 'AllowLocalIPsecPolicyMerge',
        'type'  => 'dword',
        'data'  => '0x00000001',
      )
    }
    it {
      is_expected.to contain_registry__value('PrivateLogFilePath').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging',
        'value' => 'LogFilePath',
        'type'  => 'string',
        'data'  => '%systemroot%\system32\logfiles\firewall\privatefw.log',
      )
    }
    it {
      is_expected.to contain_registry__value('PrivateLogFileSize').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging',
        'value' => 'LogFileSize',
        'type'  => 'dword',
        'data'  => '0x00004000',
      )
    }
    it {
      is_expected.to contain_registry__value('PrivateLogDroppedPackets').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging',
        'value' => 'LogDroppedPackets',
        'type'  => 'dword',
        'data'  => '0x00000001',
      )
    }
    it {
      is_expected.to contain_registry__value('PrivateLogSuccessfulConnections').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging',
        'value' => 'LogSuccessfulConnections',
        'type'  => 'dword',
        'data'  => '0x00000001',
      )
    }
    it {
      is_expected.to contain_registry__value('PublicEnableFirewall').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile',
        'value' => 'EnableFirewall',
        'type'  => 'dword',
        'data'  => '0x00000001',
      )
    }
    it {
      is_expected.to contain_registry__value('PublicDefaultInboundAction').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile',
        'value' => 'DefaultInboundAction',
        'type'  => 'dword',
        'data'  => '0x00000001',
      )
    }
    it {
      is_expected.to contain_registry__value('PublicDefaultOutboundAction').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile',
        'value' => 'DefaultOutboundAction',
        'type'  => 'dword',
        'data'  => '0x00000000',
      )
    }
    it {
      is_expected.to contain_registry__value('PublicDisableNotifications').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile',
        'value' => 'DisableNotifications',
        'type'  => 'dword',
        'data'  => '0x00000000',
      )
    }
    it {
      is_expected.to contain_registry__value('PublicAllowLocalPolicyMerge').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile',
        'value' => 'AllowLocalPolicyMerge',
        'type'  => 'dword',
        'data'  => '0x00000000',
      )
    }
    it {
      is_expected.to contain_registry__value('PublicAllowLocalIPsecPolicyMerge').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile',
        'value' => 'AllowLocalIPsecPolicyMerge',
        'type'  => 'dword',
        'data'  => '0x00000000',
      )
    }
    it {
      is_expected.to contain_registry__value('PublicLogFilePath').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging',
        'value' => 'LogFilePath',
        'type'  => 'string',
        'data'  => '%systemroot%\system32\logfiles\firewall\publicfw.log',
      )
    }
    it {
      is_expected.to contain_registry__value('PublicLogFileSize').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging',
        'value' => 'LogFileSize',
        'type'  => 'dword',
        'data'  => '0x00004000',
      )
    }
    it {
      is_expected.to contain_registry__value('PublicLogDroppedPackets').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging',
        'value' => 'LogDroppedPackets',
        'type'  => 'dword',
        'data'  => '0x00000001',
      )
    }
    it {
      is_expected.to contain_registry__value('PublicLogSuccessfulConnections').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging',
        'value' => 'LogSuccessfulConnections',
        'type'  => 'dword',
        'data'  => '0x00000001',
      )
    }
    it {
      is_expected.to contain_auditpol('Credential Validation').with(
        'success' => 'enable',
        'failure' => 'enable',
      )
    }
    it {
      is_expected.to contain_auditpol('Application Group Management').with(
        'success' => 'enable',
        'failure' => 'enable',
      )
    }
    it {
      is_expected.to contain_auditpol('Computer Account Management').with(
        'success' => 'enable',
        'failure' => 'enable',
      )
    }
    # DC ONLY
    # it {
    #   should contain_auditpol('Distribution Group Management').with(
    #     'success' => 'enable',
    #     'failure' => 'enable'
    #   )
    # }
    it {
      is_expected.to contain_auditpol('Other Account Management Events').with(
        'success' => 'enable',
        'failure' => 'enable',
      )
    }
    it {
      is_expected.to contain_auditpol('Security Group Management').with(
        'success' => 'enable',
        'failure' => 'enable',
      )
    }
    it {
      is_expected.to contain_auditpol('User Account Management').with(
        'success' => 'enable',
        'failure' => 'enable',
      )
    }
    it {
      is_expected.to contain_auditpol('Process Creation').with(
        'success' => 'enable',
        'failure' => 'disable',
      )
    }
    # DC ONLY
    # it {
    #   should contain_auditpol('Directory Service Changes').with(
    #     'success' => 'enable',
    #     'failure' => 'enable'
    #   )
    # }
    # it {
    #   should contain_auditpol('Directory Service Access').with(
    #     'success' => 'enable',
    #     'failure' => 'enable'
    #   )
    # }
    it {
      is_expected.to contain_auditpol('Account Lockout').with(
        'success' => 'enable',
        'failure' => 'disable',
      )
    }
    it {
      is_expected.to contain_auditpol('Logoff').with(
        'success' => 'enable',
        'failure' => 'disable',
      )
    }
    it {
      is_expected.to contain_auditpol('Logon').with(
        'success' => 'enable',
        'failure' => 'enable',
      )
    }
    it {
      is_expected.to contain_auditpol('Other Logon/Logoff Events').with(
        'success' => 'enable',
        'failure' => 'enable',
      )
    }
    it {
      is_expected.to contain_auditpol('Special Logon').with(
        'success' => 'enable',
        'failure' => 'disable',
      )
    }
    it {
      is_expected.to contain_auditpol('Audit Policy Change').with(
        'success' => 'enable',
        'failure' => 'enable',
      )
    }
    it {
      is_expected.to contain_auditpol('Authentication Policy Change').with(
        'success' => 'enable',
        'failure' => 'disable',
      )
    }
    it {
      is_expected.to contain_auditpol('Sensitive Privilege Use').with(
        'success' => 'enable',
        'failure' => 'enable',
      )
    }
    it {
      is_expected.to contain_auditpol('IPsec Driver').with(
        'success' => 'enable',
        'failure' => 'enable',
      )
    }
    it {
      is_expected.to contain_auditpol('Other System Events').with(
        'success' => 'enable',
        'failure' => 'enable',
      )
    }
    it {
      is_expected.to contain_auditpol('Security State Change').with(
        'success' => 'enable',
        'failure' => 'disable',
      )
    }
    it {
      is_expected.to contain_auditpol('Security System Extension').with(
        'success' => 'enable',
        'failure' => 'enable',
      )
    }
    it {
      is_expected.to contain_auditpol('System Integrity').with(
        'success' => 'enable',
        'failure' => 'enable',
      )
    }
    # L2
    # it {
    #   should contain_registry__value('AllowLLTDIOOnDomain').with(
    #     'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LLTD',
    #     'value' => 'AllowLLTDIOOnDomain',
    #     'type'  => 'dword',
    #     'data'  => '0x00000000'
    #   )
    # }
    # it {
    #   should contain_registry__value('AllowLLTDIOOnPublicNet').with(
    #     'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LLTD',
    #     'value' => 'AllowLLTDIOOnPublicNet',
    #     'type'  => 'dword',
    #     'data'  => '0x00000000'
    #   )
    # }
    # it {
    #   should contain_registry__value('EnableLLTDIO').with(
    #     'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LLTD',
    #     'value' => 'EnableLLTDIO',
    #     'type'  => 'dword',
    #     'data'  => '0x00000000'
    #   )
    # }
    # it {
    #   should contain_registry__value('ProhibitLLTDIOOnPrivateNet').with(
    #     'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LLTD',
    #     'value' => 'ProhibitLLTDIOOnPrivateNet',
    #     'type'  => 'dword',
    #     'data'  => '0x00000000'
    #   )
    # }
    # it {
    #   should contain_registry__value('AllowRspndrOnDomain').with(
    #     'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LLTD',
    #     'value' => 'AllowRspndrOnDomain',
    #     'type'  => 'dword',
    #     'data'  => '0x00000000'
    #   )
    # }
    # it {
    #   should contain_registry__value('AllowRspndrOnPublicNet').with(
    #     'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LLTD',
    #     'value' => 'AllowRspndrOnPublicNet',
    #     'type'  => 'dword',
    #     'data'  => '0x00000000'
    #   )
    # }
    # it {
    #   should contain_registry__value('EnableRspndr').with(
    #     'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LLTD',
    #     'value' => 'EnableRspndr',
    #     'type'  => 'dword',
    #     'data'  => '0x00000000'
    #   )
    # }
    # it {
    #   should contain_registry__value('ProhibitRspndrOnPrivateNet').with(
    #     'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LLTD',
    #     'value' => 'ProhibitRspndrOnPrivateNet',
    #     'type'  => 'dword',
    #     'data'  => '0x00000000'
    #   )
    # }
    # it {
    #   should contain_registry__value('PeernetDisabled').with(
    #     'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Peernet',
    #     'value' => 'Disabled',
    #     'type'  => 'dword',
    #     'data'  => '0x00000001'
    #   )
    # }
    it {
      is_expected.to contain_registry__value('NC_AllowNetBridge_NLA').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Network Connections',
        'value' => 'NC_AllowNetBridge_NLA',
        'type'  => 'dword',
        'data'  => '0x00000000',
      )
    }
    it {
      is_expected.to contain_registry__value('NC_StdDomainUserSetLocation').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Network Connections',
        'value' => 'NC_StdDomainUserSetLocation',
        'type'  => 'dword',
        'data'  => '0x00000001',
      )
    }
    # it {
    #   should contain_registry__value('EnableRegistrars').with(
    #     'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars',
    #     'value' => 'EnableRegistrars',
    #     'type'  => 'dword',
    #     'data'  => '0x00000000'
    #   )
    # }
    # it {
    #   should contain_registry__value('DisableWPDRegistrar').with(
    #     'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars',
    #     'value' => 'DisableWPDRegistrar',
    #     'type'  => 'dword',
    #     'data'  => '0x00000000'
    #   )
    # }
    # it {
    #   should contain_registry__value('DisableUPnPRegistrar').with(
    #     'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars',
    #     'value' => 'DisableUPnPRegistrar',
    #     'type'  => 'dword',
    #     'data'  => '0x00000000'
    #   )
    # }
    # it {
    #   should contain_registry__value('DisableInBand802DOT11Registrar').with(
    #     'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars',
    #     'value' => 'DisableInBand802DOT11Registrar',
    #     'type'  => 'dword',
    #     'data'  => '0x00000000'
    #   )
    # }
    # it {
    #   should contain_registry__value('DisableFlashConfigRegistrar').with(
    #     'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars',
    #     'value' => 'DisableFlashConfigRegistrar',
    #     'type'  => 'dword',
    #     'data'  => '0x00000000'
    #   )
    # }
    # it {
    #   should contain_registry__value('DisableWcnUi').with(
    #     'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WCN\UI',
    #     'value' => 'DisableWcnUi',
    #     'type'  => 'dword',
    #     'data'  => '0x00000001'
    #   )
    # }
    it {
      is_expected.to contain_registry__value('AllowRemoteRPC').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Settings',
        'value' => 'AllowRemoteRPC',
        'type'  => 'dword',
        'data'  => '0x00000000',
      )
    }
    it {
      is_expected.to contain_registry__value('NoBackgroundPolicy').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}',
        'value' => 'NoBackgroundPolicy',
        'type'  => 'dword',
        'data'  => '0x00000000',
      )
    }
    it {
      is_expected.to contain_registry__value('NoGPOListChange').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}',
        'value' => 'NoGPOListChange',
        'type'  => 'dword',
        'data'  => '0x00000000',
      )
    }
    it {
      is_expected.to contain_registry__value('LogonType').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System',
        'value' => 'LogonType',
        'type'  => 'dword',
        'data'  => '0x00000000',
      )
    }
    it {
      is_expected.to contain_registry__value('fAllowUnsolicited').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services',
        'value' => 'fAllowUnsolicited',
        'type'  => 'dword',
        'data'  => '0x00000000',
      )
    }
    it {
      is_expected.to contain_registry__value('fAllowToGetHelp').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services',
        'value' => 'fAllowToGetHelp',
        'type'  => 'dword',
        'data'  => '0x00000000',
      )
    }
    it {
      is_expected.to contain_registry__value('EnableAuthEpResolution').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Rpc',
        'value' => 'EnableAuthEpResolution',
        'type'  => 'dword',
        'data'  => '0x00000001',
      )
    }
    it {
      is_expected.to contain_registry__value('NoAutoplayfornonVolume').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer',
        'value' => 'NoAutoplayfornonVolume',
        'type'  => 'dword',
        'data'  => '0x00000001',
      )
    }
    it {
      is_expected.to contain_registry__value('NoAutorun').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer',
        'value' => 'NoAutorun',
        'type'  => 'dword',
        'data'  => '0x00000001',
      )
    }
    it {
      is_expected.to contain_registry__value('NoDriveTypeAutoRun').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer',
        'value' => 'NoDriveTypeAutoRun',
        'type'  => 'dword',
        'data'  => '0x000000ff',
      )
    }
    it {
      is_expected.to contain_registry__value('EnumerateAdministrators').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI',
        'value' => 'EnumerateAdministrators',
        'type'  => 'dword',
        'data'  => '0x00000000',
      )
    }
    it {
      is_expected.to contain_registry__value('TurnOffSidebar').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Windows\Sidebar',
        'value' => 'TurnOffSidebar',
        'type'  => 'dword',
        'data'  => '0x00000001',
      )
    }
    it {
      is_expected.to contain_registry__value('TurnOffUserInstalledGadgets').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Windows\Sidebar',
        'value' => 'TurnOffUserInstalledGadgets',
        'type'  => 'dword',
        'data'  => '0x00000001',
      )
    }
    it {
      is_expected.to contain_registry__value('ApplicationRetention').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application',
        'value' => 'Retention',
        'type'  => 'string',
        'data'  => '0',
      )
    }
    it {
      is_expected.to contain_registry__value('ApplicationMaxSize').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application',
        'value' => 'MaxSize',
        'type'  => 'dword',
        'data'  => '0x00008000',
      )
    }
    it {
      is_expected.to contain_registry__value('SecurityRetention').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security',
        'value' => 'Retention',
        'type'  => 'string',
        'data'  => '0',
      )
    }
    it {
      is_expected.to contain_registry__value('SecurityMaxSize').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security',
        'value' => 'MaxSize',
        'type'  => 'dword',
        'data'  => '0x00030000',
      )
    }
    it {
      is_expected.to contain_registry__value('SetupRetention').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup',
        'value' => 'Retention',
        'type'  => 'string',
        'data'  => '0',
      )
    }
    it {
      is_expected.to contain_registry__value('SetupMaxSize').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup',
        'value' => 'MaxSize',
        'type'  => 'dword',
        'data'  => '0x00008000',
      )
    }
    it {
      is_expected.to contain_registry__value('SystemRetention').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\System',
        'value' => 'Retention',
        'type'  => 'string',
        'data'  => '0',
      )
    }
    it {
      is_expected.to contain_registry__value('SystemMaxSize').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\System',
        'value' => 'MaxSize',
        'type'  => 'dword',
        'data'  => '0x00008000',
      )
    }
    it {
      is_expected.to contain_registry__value('NoDataExecutionPrevention').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer',
        'value' => 'NoDataExecutionPrevention',
        'type'  => 'dword',
        'data'  => '0x00000000',
      )
    }
    it {
      is_expected.to contain_registry__value('NoHeapTerminationOnCorruption').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer',
        'value' => 'NoHeapTerminationOnCorruption',
        'type'  => 'dword',
        'data'  => '0x00000000',
      )
    }
    it {
      is_expected.to contain_registry__value('PreXPSP2ShellProtocolBehavior').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer',
        'value' => 'PreXPSP2ShellProtocolBehavior',
        'type'  => 'dword',
        'data'  => '0x00000000',
      )
    }
    # level 2
    # it {
    #   should contain_registry__value('DisableLocation').with(
    #     'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors',
    #     'value' => 'DisableLocation',
    #     'type'  => 'dword',
    #     'data'  => '0x00000001'
    #   )
    # }
    it {
      is_expected.to contain_registry__value('DisablePasswordSaving').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services',
        'value' => 'DisablePasswordSaving',
        'type'  => 'dword',
        'data'  => '0x00000001',
      )
    }
    # it {
    #   should contain_registry__value('fSingleSessionPerUser').with(
    #     'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services',
    #     'value' => 'fSingleSessionPerUser',
    #     'type'  => 'dword',
    #     'data'  => '0x00000001'
    #   )
    # }
    # it {
    #   should contain_registry__value('fDisableCcm').with(
    #     'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services',
    #     'value' => 'fDisableCcm',
    #     'type'  => 'dword',
    #     'data'  => '0x00000001'
    #   )
    # }
    it {
      is_expected.to contain_registry__value('fDisableCdm').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services',
        'value' => 'fDisableCdm',
        'type'  => 'dword',
        'data'  => '0x00000001',
      )
    }
    # level 2
    # it {
    #   should contain_registry__value('fDisableLPT').with(
    #     'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services',
    #     'value' => 'fDisableLPT',
    #     'type'  => 'dword',
    #     'data'  => '0x00000001'
    #   )
    # # }
    # it {
    #   should contain_registry__value('fDisablePNPRedir').with(
    #     'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services',
    #     'value' => 'fDisablePNPRedir',
    #     'type'  => 'dword',
    #     'data'  => '0x00000001'
    #   )
    # }
    it {
      is_expected.to contain_registry__value('fPromptForPassword').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services',
        'value' => 'fPromptForPassword',
        'type'  => 'dword',
        'data'  => '0x00000001',
      )
    }
    it {
      is_expected.to contain_registry__value('fEncryptRPCTraffic').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services',
        'value' => 'fEncryptRPCTraffic',
        'type'  => 'dword',
        'data'  => '0x00000001',
      )
    }
    it {
      is_expected.to contain_registry__value('MinEncryptionLevel').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services',
        'value' => 'MinEncryptionLevel',
        'type'  => 'dword',
        'data'  => '0x00000003',
      )
    }
    # level 2
    # it {
    #   should contain_registry__value('MaxIdleTime').with(
    #     'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services',
    #     'value' => 'MaxIdleTime',
    #     'type'  => 'dword',
    #     'data'  => '0x000dbba0'
    #   )
    # }
    # it {
    #   should contain_registry__value('MaxDisconnectionTime').with(
    #     'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services',
    #     'value' => 'MaxDisconnectionTime',
    #     'type'  => 'dword',
    #     'data'  => '0x0000ea60'
    #   )
    # }
    it {
      is_expected.to contain_registry__value('DeleteTempDirsOnExit').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services',
        'value' => 'DeleteTempDirsOnExit',
        'type'  => 'dword',
        'data'  => '0x00000001',
      )
    }
    it {
      is_expected.to contain_registry__value('PerSessionTempDir').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services',
        'value' => 'PerSessionTempDir',
        'type'  => 'dword',
        'data'  => '0x00000001',
      )
    }
    it {
      is_expected.to contain_registry__value('DisableEnclosureDownload').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds',
        'value' => 'DisableEnclosureDownload',
        'type'  => 'dword',
        'data'  => '0x00000001',
      )
    }
    it {
      is_expected.to contain_registry__value('DefaultConsent').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting\Consent',
        'value' => 'DefaultConsent',
        'type'  => 'dword',
        'data'  => '0x00000001',
      )
    }
    it {
      is_expected.to contain_registry__value('EnableUserControl').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer',
        'value' => 'EnableUserControl',
        'type'  => 'dword',
        'data'  => '0x00000000',
      )
    }
    it {
      is_expected.to contain_registry__value('AlwaysInstallElevated').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer',
        'value' => 'AlwaysInstallElevated',
        'type'  => 'dword',
        'data'  => '0x00000000',
      )
    }
    it {
      is_expected.to contain_registry__value('ClientAllowBasic').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client',
        'value' => 'AllowBasic',
        'type'  => 'dword',
        'data'  => '0x00000000',
      )
    }
    it {
      is_expected.to contain_registry__value('ClientAllowUnencryptedTraffic').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client',
        'value' => 'AllowUnencryptedTraffic',
        'type'  => 'dword',
        'data'  => '0x00000000',
      )
    }
    it {
      is_expected.to contain_registry__value('AllowDigest').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client',
        'value' => 'AllowDigest',
        'type'  => 'dword',
        'data'  => '0x00000000',
      )
    }
    it {
      is_expected.to contain_registry__value('ServiceAllowBasic').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service',
        'value' => 'AllowBasic',
        'type'  => 'dword',
        'data'  => '0x00000000',
      )
    }
    it {
      is_expected.to contain_registry__value('ServiceAllowUnencryptedTraffic').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service',
        'value' => 'AllowUnencryptedTraffic',
        'type'  => 'dword',
        'data'  => '0x00000000',
      )
    }
    # level 2
    # it {
    #   should contain_registry__value('AllowRemoteShellAccess').with(
    #     'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\WinRS',
    #     'value' => 'AllowRemoteShellAccess',
    #     'type'  => 'dword',
    #     'data'  => '0x00000000'
    #   )
    # }
    it {
      is_expected.to contain_registry__value('NoAutoUpdate').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU',
        'value' => 'NoAutoUpdate',
        'type'  => 'dword',
        'data'  => '0x00000000',
      )
    }
    it {
      is_expected.to contain_registry__value('ScheduledInstallDay').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU',
        'value' => 'ScheduledInstallDay',
        'type'  => 'dword',
        'data'  => '0x00000000',
      )
    }
    it {
      is_expected.to contain_registry__value('NoAUAsDefaultShutdownOption').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU',
        'value' => 'NoAUAsDefaultShutdownOption',
        'type'  => 'dword',
        'data'  => '0x00000000',
      )
    }
    it {
      is_expected.to contain_registry__value('NoAUShutdownOption').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU',
        'value' => 'NoAUShutdownOption',
        'type'  => 'dword',
        'data'  => '0x00000000',
      )
    }
    it {
      is_expected.to contain_registry__value('NoAutoRebootWithLoggedOnUsers').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU',
        'value' => 'NoAutoRebootWithLoggedOnUsers',
        'type'  => 'dword',
        'data'  => '0x00000000',
      )
    }
    it {
      is_expected.to contain_registry__value('RescheduleWaitTimeEnabled').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU',
        'value' => 'RescheduleWaitTimeEnabled',
        'type'  => 'dword',
        'data'  => '0x00000001',
      )
    }
    it {
      is_expected.to contain_registry__value('RescheduleWaitTime').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU',
        'value' => 'RescheduleWaitTime',
        'type'  => 'dword',
        'data'  => '0x00000001',
      )
    }
  end
  context 'Domain Controller Level 1' do
    let(:facts) { { 'operatingsystem' => 'windows' } }
    # it { is_expected.to compile }
    let(:params) { { 'is_domain_controller' => true } }

    it {
      is_expected.to contain_class('Harden_windows_server::Configure') {}
    }
    it {
      is_expected.to contain_local_security_policy('Enforce password history').with(
        'ensure' => 'present',
        'policy_setting' => 'PasswordHistorySize',
        'policy_type' => 'System Access',
        'policy_value' => '24',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Maximum password age').with(
        'ensure'         => 'present',
        'policy_setting' => 'MaximumPasswordAge',
        'policy_type'    => 'System Access',
        'policy_value'   => '42',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Minimum password age').with(
        'ensure'         => 'present',
        'policy_setting' => 'MinimumPasswordAge',
        'policy_type'    => 'System Access',
        'policy_value'   => '1',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Minimum password length').with(
        'ensure'         => 'present',
        'policy_setting' => 'MinimumPasswordLength',
        'policy_type'    => 'System Access',
        'policy_value'   => '14',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Password must meet complexity requirements').with(
        'ensure'         => 'present',
        'policy_setting' => 'PasswordComplexity',
        'policy_type'    => 'System Access',
        'policy_value'   => 'enabled',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Store passwords using reversible encryption').with(
        'ensure'         => 'present',
        'policy_setting' => 'ClearTextPassword',
        'policy_type'    => 'System Access',
        'policy_value'   => 'disabled',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Account lockout duration').with(
        'ensure'         => 'present',
        'policy_setting' => 'LockoutDuration',
        'policy_type'    => 'System Access',
        'policy_value'   => '30',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Account lockout threshold').with(
        'ensure'         => 'present',
        'policy_setting' => 'LockoutBadCount',
        'policy_type'    => 'System Access',
        'policy_value'   => '10',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Reset account lockout counter after').with(
        'ensure'         => 'present',
        'policy_setting' => 'ResetLockoutCount',
        'policy_type'    => 'System Access',
        'policy_value'   => '30',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Access Credential Manager as a trusted caller').with(
        'ensure'         => 'absent',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Access this computer from the network').with(
        'ensure'         => 'present',
        'policy_setting' => 'SeNetworkLogonRight',
        'policy_type'    => 'Privilege Rights',
        'policy_value'   => 'set: Administrators, Authenticated Users, Enterprise Domain Controllers',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Act as part of the operating system').with(
        'ensure'         => 'absent',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Add workstations to domain').with(
        'ensure'         => 'present',
        'policy_setting' => 'SeMachineAccountPrivilege',
        'policy_type'    => 'Privilege Rights',
        'policy_value'   => 'set: Administrators',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Adjust memory quotas for a process').with(
        'ensure'         => 'present',
        'policy_setting' => 'SeIncreaseQuotaPrivilege',
        'policy_type'    => 'Privilege Rights',
        'policy_value'   => 'set: Local Service, Network Service, Administrators',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Allow log on locally').with(
        'ensure'         => 'present',
        'policy_setting' => 'SeInteractiveLogonRight',
        'policy_type'    => 'Privilege Rights',
        'policy_value'   => 'set: Administrators, Enterprise Domain Controllers',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Allow log on through Remote Desktop Services').with(
        'ensure'         => 'present',
        'policy_setting' => 'SeRemoteInteractiveLogonRight',
        'policy_type'    => 'Privilege Rights',
        'policy_value'   => 'set: Administrators',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Back up files and directories').with(
        'ensure'         => 'present',
        'policy_setting' => 'SeBackupPrivilege',
        'policy_type'    => 'Privilege Rights',
        'policy_value'   => 'set: Administrators',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Change the system time').with(
        'ensure'         => 'present',
        'policy_setting' => 'SeSystemtimePrivilege',
        'policy_type'    => 'Privilege Rights',
        'policy_value'   => 'set: Local Service, Administrators',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Change the time zone').with(
        'ensure'         => 'present',
        'policy_setting' => 'SeTimeZonePrivilege',
        'policy_type'    => 'Privilege Rights',
        'policy_value'   => 'set: Local Service, Administrators',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Create a pagefile').with(
        'ensure'         => 'present',
        'policy_setting' => 'SeCreatePagefilePrivilege',
        'policy_type'    => 'Privilege Rights',
        'policy_value'   => 'set: Administrators',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Create a token object').with(
        'ensure'         => 'absent',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Create global objects').with(
        'ensure'         => 'present',
        'policy_setting' => 'SeCreateGlobalPrivilege',
        'policy_type'    => 'Privilege Rights',
        'policy_value'   => 'set: Local Service, Network Service, Administrators, Service',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Create permanent shared objects').with(
        'ensure'         => 'absent',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Create symbolic links').with(
        'ensure'         => 'present',
        'policy_setting' => 'SeCreateSymbolicLinkPrivilege',
        'policy_type'    => 'Privilege Rights',
        'policy_value'   => 'set: Administrators',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Debug programs').with(
        'ensure'         => 'present',
        'policy_setting' => 'SeDebugPrivilege',
        'policy_type'    => 'Privilege Rights',
        'policy_value'   => 'set: Administrators',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Deny access to this computer from the network').with(
        'ensure'         => 'present',
        'policy_setting' => 'SeDenyNetworkLogonRight',
        'policy_type'    => 'Privilege Rights',
        'policy_value'   => 'set: Guests, Local',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Deny log on as a batch job').with(
        'ensure'         => 'present',
        'policy_setting' => 'SeDenyBatchLogonRight',
        'policy_type'    => 'Privilege Rights',
        'policy_value'   => 'set: Guests',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Deny log on as a service').with(
        'ensure'         => 'present',
        'policy_setting' => 'SeDenyServiceLogonRight',
        'policy_type'    => 'Privilege Rights',
        'policy_value'   => 'set: Guests',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Deny log on locally').with(
        'ensure'         => 'present',
        'policy_setting' => 'SeDenyInteractiveLogonRight',
        'policy_type'    => 'Privilege Rights',
        'policy_value'   => 'set: Guests',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Deny log on through Remote Desktop Services').with(
        'ensure'         => 'present',
        'policy_setting' => 'SeDenyRemoteInteractiveLogonRight',
        'policy_type'    => 'Privilege Rights',
        'policy_value'   => 'set: Guests, Local',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Enable computer and user accounts to be trusted for delegation').with(
        'ensure'         => 'present',
        'policy_setting' => 'SeEnableDelegationPrivilege',
        'policy_type'    => 'Privilege Rights',
        'policy_value'   => 'set: Administrators',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Force shutdown from a remote system').with(
        'ensure'         => 'present',
        'policy_setting' => 'SeRemoteShutdownPrivilege',
        'policy_type'    => 'Privilege Rights',
        'policy_value'   => 'set: Administrators',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Generate security audits').with(
        'ensure'         => 'present',
        'policy_setting' => 'SeAuditPrivilege',
        'policy_type'    => 'Privilege Rights',
        'policy_value'   => 'set: Local Service, Network Service',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Impersonate a client after authentication').with(
        'ensure'         => 'present',
        'policy_setting' => 'SeImpersonatePrivilege',
        'policy_type'    => 'Privilege Rights',
        'policy_value'   => 'set: Local Service, Network Service, Administrators, Service',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Increase scheduling priority').with(
        'ensure'         => 'present',
        'policy_setting' => 'SeIncreaseBasePriorityPrivilege',
        'policy_type'    => 'Privilege Rights',
        'policy_value'   => 'set: Administrators',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Load and unload device drivers').with(
        'ensure'         => 'present',
        'policy_setting' => 'SeLoadDriverPrivilege',
        'policy_type'    => 'Privilege Rights',
        'policy_value'   => 'set: Administrators',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Lock pages in memory').with(
        'ensure'         => 'absent',
      )
    }
    # level 2
    # it {
    #   should contain_local_security_policy('Log on as a batch job').with(
    #     'ensure'         => 'present',
    #     'policy_setting' => 'SeBatchLogonRight',
    #     'policy_type'    => 'Privilege Rights',
    #     'policy_value'   => '*S-1-5-32-544,*S-1-5-32-551,*S-1-5-32-559'
    #   )
    # }
    it {
      is_expected.to contain_local_security_policy('Manage auditing and security log').with(
        'ensure'         => 'present',
        'policy_setting' => 'SeSecurityPrivilege',
        'policy_type'    => 'Privilege Rights',
        'policy_value'   => 'set: Administrators',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Modify an object label').with(
        'ensure'         => 'absent',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Modify firmware environment values').with(
        'ensure'         => 'present',
        'policy_setting' => 'SeSystemEnvironmentPrivilege',
        'policy_type'    => 'Privilege Rights',
        'policy_value'   => 'set: Administrators',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Perform volume maintenance tasks').with(
        'ensure'         => 'present',
        'policy_setting' => 'SeManageVolumePrivilege',
        'policy_type'    => 'Privilege Rights',
        'policy_value'   => 'set: Administrators',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Profile single process').with(
        'ensure'         => 'present',
        'policy_setting' => 'SeProfileSingleProcessPrivilege',
        'policy_type'    => 'Privilege Rights',
        'policy_value'   => 'set: Administrators',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Profile system performance').with(
        'ensure'         => 'present',
        'policy_setting' => 'SeSystemProfilePrivilege',
        'policy_type'    => 'Privilege Rights',
        'policy_value'   => 'set: Administrators, NT SERVICE\WdiServiceHost',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Replace a process level token').with(
        'ensure'         => 'present',
        'policy_setting' => 'SeAssignPrimaryTokenPrivilege',
        'policy_type'    => 'Privilege Rights',
        'policy_value'   => 'set: Local Service, Network Service',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Restore files and directories').with(
        'ensure'         => 'present',
        'policy_setting' => 'SeRestorePrivilege',
        'policy_type'    => 'Privilege Rights',
        'policy_value'   => 'set: Administrators',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Shut down the system').with(
        'ensure'         => 'present',
        'policy_setting' => 'SeShutdownPrivilege',
        'policy_type'    => 'Privilege Rights',
        'policy_value'   => 'set: Administrators',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Synchronize directory service data').with(
        'ensure'         => 'absent',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Take ownership of files or other objects').with(
        'ensure'         => 'present',
        'policy_setting' => 'SeTakeOwnershipPrivilege',
        'policy_type'    => 'Privilege Rights',
        'policy_value'   => 'set: Administrators',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Accounts: Limit local account use of blank passwords to console logon only').with(
        'ensure'         => 'present',
        'policy_setting' => 'MACHINE\System\CurrentControlSet\Control\Lsa\LimitBlankPasswordUse',
        'policy_type'    => 'Registry Values',
        'policy_value'   => 'enabled',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Accounts: Rename administrator account').with(
        'ensure'         => 'present',
        'policy_setting' => 'NewAdministratorName',
        'policy_type'    => 'System Access',
        'policy_value'   => '"adminaccount"',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Accounts: Rename guest account').with(
        'ensure'         => 'present',
        'policy_setting' => 'NewGuestName',
        'policy_type'    => 'System Access',
        'policy_value'   => '"guestaccount"',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings').with(
        'ensure'         => 'present',
        'policy_setting' => 'MACHINE\System\CurrentControlSet\Control\Lsa\SCENoApplyLegacyAuditPolicy',
        'policy_type'    => 'Registry Values',
        'policy_value'   => 'enabled',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Audit: Shut down system immediately if unable to log security audits').with(
        'ensure'         => 'present',
        'policy_setting' => 'MACHINE\System\CurrentControlSet\Control\Lsa\CrashOnAuditFail',
        'policy_type'    => 'Registry Values',
        'policy_value'   => 'disabled',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Devices: Allowed to format and eject removable media').with(
        'ensure'         => 'present',
        'policy_setting' => 'MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\AllocateDASD',
        'policy_type'    => 'Registry Values',
        'policy_value'   => 'Administrators',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Devices: Prevent users from installing printer drivers').with(
        'ensure'         => 'present',
        'policy_setting' => 'MACHINE\System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers\AddPrinterDrivers',
        'policy_type'    => 'Registry Values',
        'policy_value'   => 'enabled',
      )
    }
    it {
      is_expected.to contain_registry__value('SubmitControl').with(
        'key'   => 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa',
        'value' => 'SubmitControl',
        'type'  => 'dword',
        'data'  => '0x00000000',
      )
    }
    it {
      is_expected.to contain_registry__value('LDAPServerIntegrity').with(
        'key'   => 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Service\NTDS\Parameters',
        'value' => 'LDAPServerIntegrity',
        'type'  => 'dword',
        'data'  => '0x00000002',
      )
    }
    it {
      is_expected.to contain_registry__value('RefusePasswordChange').with(
        'key'   => 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Service\Netlogon\Parameters',
        'value' => 'RefusePasswordChange',
        'type'  => 'dword',
        'data'  => '0x00000000',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Domain member: Digitally encrypt or sign secure channel data (always)').with(
        'ensure'         => 'present',
        'policy_setting' => 'MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\RequireSignOrSeal',
        'policy_type'    => 'Registry Values',
        'policy_value'   => 'enabled',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Domain member: Digitally encrypt secure channel data (when possible)').with(
        'ensure'         => 'present',
        'policy_setting' => 'MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\SealSecureChannel',
        'policy_type'    => 'Registry Values',
        'policy_value'   => 'enabled',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Domain member: Digitally sign secure channel data (when possible)').with(
        'ensure'         => 'present',
        'policy_setting' => 'MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\SignSecureChannel',
        'policy_type'    => 'Registry Values',
        'policy_value'   => 'enabled',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Domain member: Disable machine account password changes').with(
        'ensure'         => 'present',
        'policy_setting' => 'MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\DisablePasswordChange',
        'policy_type'    => 'Registry Values',
        'policy_value'   => 'disabled',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Domain member: Maximum machine account password age').with(
        'ensure'         => 'present',
        'policy_setting' => 'MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\MaximumPasswordAge',
        'policy_type'    => 'Registry Values',
        'policy_value'   => '4,30',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Domain member: Require strong (Windows 2000 or later) session key').with(
        'ensure'         => 'present',
        'policy_setting' => 'MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\RequireStrongKey',
        'policy_type'    => 'Registry Values',
        'policy_value'   => 'enabled',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Interactive logon: Do not display last user name').with(
        'ensure'         => 'present',
        'policy_setting' => 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\DontDisplayLastUserName',
        'policy_type'    => 'Registry Values',
        'policy_value'   => 'enabled',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Interactive logon: Do not require CTRL+ALT+DEL').with(
        'ensure'         => 'present',
        'policy_setting' => 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\DisableCAD',
        'policy_type'    => 'Registry Values',
        'policy_value'   => 'disabled',
      )
    }
    # it {
    #   should contain_local_security_policy('Interactive logon: Message text for users attempting to log on').with(
    #     'ensure'         => 'present',
    #     'policy_setting' => 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\LegalNoticeText',
    #     'policy_type'    => 'Registry Values',
    #     'policy_value'   => '7,Welcome!'
    #   )
    # }
    # it {
    #   should contain_local_security_policy('Interactive logon: Message title for users attempting to log on').with(
    #     'ensure'         => 'present',
    #     'policy_setting' => 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\LegalNoticeCaption',
    #     'policy_type'    => 'Registry Values',
    #     'policy_value'   => '1,"Title Bar"'
    #   )
    # }
    # L2 MS
    # it {
    #   should contain_local_security_policy('Interactive logon: Number of previous logons to cache (in case domain controller is not available)').with(
    #     'ensure'         => 'present',
    #     'policy_setting' => 'MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\CachedLogonsCount',
    #     'policy_type'    => 'Registry Values',
    #     'policy_value'   => '1,"4"'
    #   )
    # }
    it {
      is_expected.to contain_local_security_policy('Interactive logon: Prompt user to change password before expiration').with(
        'ensure'         => 'present',
        'policy_setting' => 'MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\PasswordExpiryWarning',
        'policy_type'    => 'Registry Values',
        'policy_value'   => '4,5',
      )
    }
    # MS
    # it {
    #   should contain_local_security_policy('Interactive logon: Require Domain Controller authentication to unlock workstation').with(
    #     'ensure'         => 'present',
    #     'policy_setting' => 'MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\ForceUnlockLogon',
    #     'policy_type'    => 'Registry Values',
    #     'policy_value'   => '4,1'
    #   )
    # }
    it {
      is_expected.to contain_local_security_policy('Interactive logon: Smart card removal behavior').with(
        'ensure'         => 'present',
        'policy_setting' => 'MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\ScRemoveOption',
        'policy_type'    => 'Registry Values',
        'policy_value'   => 'Lock Workstation',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Microsoft network client: Digitally sign communications (always)').with(
        'ensure'         => 'present',
        'policy_setting' => 'MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\RequireSecuritySignature',
        'policy_type'    => 'Registry Values',
        'policy_value'   => 'enabled',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Microsoft network client: Digitally sign communications (if server agrees)').with(
        'ensure'         => 'present',
        'policy_setting' => 'MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\EnableSecuritySignature',
        'policy_type'    => 'Registry Values',
        'policy_value'   => 'enabled',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Microsoft network client: Send unencrypted password to third-party SMB servers').with(
        'ensure'         => 'present',
        'policy_setting' => 'MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\EnablePlainTextPassword',
        'policy_type'    => 'Registry Values',
        'policy_value'   => 'disabled',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Microsoft network server: Amount of idle time required before suspending session').with(
        'ensure'         => 'present',
        'policy_setting' => 'MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\AutoDisconnect',
        'policy_type'    => 'Registry Values',
        'policy_value'   => '4,15',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Microsoft network server: Digitally sign communications (always)').with(
        'ensure'         => 'present',
        'policy_setting' => 'MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\RequireSecuritySignature',
        'policy_type'    => 'Registry Values',
        'policy_value'   => 'enabled',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Microsoft network server: Digitally sign communications (if client agrees)').with(
        'ensure'         => 'present',
        'policy_setting' => 'MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\EnableSecuritySignature',
        'policy_type'    => 'Registry Values',
        'policy_value'   => 'enabled',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Microsoft network server: Disconnect clients when logon hours expire').with(
        'ensure'         => 'present',
        'policy_setting' => 'MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\EnableForcedLogOff',
        'policy_type'    => 'Registry Values',
        'policy_value'   => 'enabled',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Network access: Allow anonymous SID/name translation').with(
        'ensure'         => 'present',
        'policy_setting' => 'LSAAnonymousNameLookup',
        'policy_type'    => 'System Access',
        'policy_value'   => 'disabled',
      )
    }
    # Both MS
    # it {
    #   should contain_local_security_policy('Network access: Do not allow anonymous enumeration of SAM accounts').with(
    #     'ensure'         => 'present',
    #     'policy_setting' => 'MACHINE\System\CurrentControlSet\Control\Lsa\RestrictAnonymousSAM',
    #     'policy_type'    => 'Registry Values',
    #     'policy_value'   => '4,1'
    #   )
    # }
    # it {
    #   should contain_local_security_policy('Network access: Do not allow anonymous enumeration of SAM accounts and shares').with(
    #     'ensure'         => 'present',
    #     'policy_setting' => 'MACHINE\System\CurrentControlSet\Control\Lsa\RestrictAnonymous',
    #     'policy_type'    => 'Registry Values',
    #     'policy_value'   => '4,1'
    #   )
    # }
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
      is_expected.to contain_local_security_policy('Network access: Let Everyone permissions apply to anonymous users').with(
        'ensure'         => 'present',
        'policy_setting' => 'MACHINE\System\CurrentControlSet\Control\Lsa\EveryoneIncludesAnonymous',
        'policy_type'    => 'Registry Values',
        'policy_value'   => 'disabled',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Network access: Remotely accessible registry paths').with(
        'ensure'         => 'present',
        'policy_setting' => 'MACHINE\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths\Machine',
        'policy_type'    => 'Registry Values',
        'policy_value'   => '7,System\CurrentControlSet\Control\ProductOptions,System\CurrentControlSet\Control\Server Applications,Software\Microsoft\Windows NT\CurrentVersion',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Network access: Remotely accessible registry paths and sub-paths').with(
        'ensure'         => 'present',
        'policy_setting' => 'MACHINE\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths\Machine',
        'policy_type'    => 'Registry Values',
        'policy_value'   => '7,System\CurrentControlSet\Control\Print\Printers,System\CurrentControlSet\Services\Eventlog,' \
                            'Software\Microsoft\OLAP Server,Software\Microsoft\Windows NT\CurrentVersion\Print,' \
                            'Software\Microsoft\Windows NT\CurrentVersion\Windows,System\CurrentControlSet\Control\ContentIndex,' \
                            'System\CurrentControlSet\Control\Terminal Server,' \
                            'System\CurrentControlSet\Control\Terminal Server\UserConfig,' \
                            'System\CurrentControlSet\Control\Terminal Server\DefaultUserConfiguration,' \
                            'Software\Microsoft\Windows NT\CurrentVersion\Perflib,System\CurrentControlSet\Services\SysmonLog',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Network access: Restrict anonymous access to Named Pipes and Shares').with(
        'ensure'         => 'present',
        'policy_setting' => 'MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\RestrictNullSessAccess',
        'policy_type'    => 'Registry Values',
        'policy_value'   => 'enabled',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Network access: Sharing and security model for local accounts').with(
        'ensure'         => 'present',
        'policy_setting' => 'MACHINE\System\CurrentControlSet\Control\Lsa\ForceGuest',
        'policy_type'    => 'Registry Values',
        'policy_value'   => 'Classic - local users authenticate as themselves',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Network security: All Local System to use computer identity for NTLM').with(
        'ensure'         => 'present',
        'policy_setting' => 'MACHINE\System\CurrentControlSet\Control\Lsa\UseMachineId',
        'policy_type'    => 'Registry Values',
        'policy_value'   => 'enabled',
      )
    }
    it {
      is_expected.to contain_registry__value('allownullsessionfallback').with(
        'key'   => 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0',
        'value' => 'allownullsessionfallback',
        'type'  => 'dword',
        'data'  => '0x00000000',
      )
    }
    it {
      is_expected.to contain_registry__value('AllowOnlineID').with(
        'key'   => 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\pku2u',
        'value' => 'AllowOnlineID',
        'type'  => 'dword',
        'data'  => '0x00000000',
      )
    }
    it {
      is_expected.to contain_registry__value('SupportedEncryptionTypes').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters',
        'value' => 'SupportedEncryptionTypes',
        'type'  => 'dword',
        'data'  => '0x7ffffffc',
      )
    }
    it {
      is_expected.to contain_registry__value('NoLmHash').with(
        'key'   => 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa',
        'value' => 'NoLmHash',
        'type'  => 'dword',
        'data'  => '0x00000001',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Network security: Force logoff when logon hours expire').with(
        'ensure'         => 'present',
        'policy_setting' => 'ForceLogoffWhenHourExpire',
        'policy_type'    => 'System Access',
        'policy_value'   => '1',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Network security: LAN Manager authentication level').with(
        'ensure'         => 'present',
        'policy_setting' => 'MACHINE\System\CurrentControlSet\Control\Lsa\LmCompatibilityLevel',
        'policy_type'    => 'Registry Values',
        'policy_value'   => '4,5',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Network security: LDAP client signing requirements').with(
        'ensure'         => 'present',
        'policy_setting' => 'MACHINE\System\CurrentControlSet\Services\LDAP\LDAPClientIntegrity',
        'policy_type'    => 'Registry Values',
        'policy_value'   => 'enabled',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Network security: Minimum session security for NTLM SSP based (including secure RPC) clients').with(
        'ensure'         => 'present',
        'policy_setting' => 'MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\NTLMMinClientSec',
        'policy_type'    => 'Registry Values',
        'policy_value'   => '4,537395200',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Network security: Minimum session security for NTLM SSP based (including secure RPC) servers').with(
        'ensure'         => 'present',
        'policy_setting' => 'MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\NTLMMinServerSec',
        'policy_type'    => 'Registry Values',
        'policy_value'   => '4,537395200',
      )
    }
    it {
      is_expected.to contain_local_security_policy('Shutdown: Allow system to be shut down without having to log on').with(
        'ensure'         => 'present',
        'policy_setting' => 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ShutdownWithoutLogon',
        'policy_type'    => 'Registry Values',
        'policy_value'   => 'disabled',
      )
    }
    it {
      is_expected.to contain_local_security_policy('System objects: Require case insensitivity for non-Windows subsystems').with(
        'ensure'         => 'present',
        'policy_setting' => 'MACHINE\System\CurrentControlSet\Control\Session Manager\Kernel\ObCaseInsensitive',
        'policy_type'    => 'Registry Values',
        'policy_value'   => 'enabled',
      )
    }
    it {
      is_expected.to contain_local_security_policy('System objects: Strengthen default permissions of internal system objects (e.g., Symbolic Links)').with(
        'ensure'         => 'present',
        'policy_setting' => 'MACHINE\System\CurrentControlSet\Control\Session Manager\ProtectionMode',
        'policy_type'    => 'Registry Values',
        'policy_value'   => 'enabled',
      )
    }
    it {
      is_expected.to contain_local_security_policy('System settings: Optional subsystems').with(
        'ensure'         => 'present',
        'policy_setting' => 'MACHINE\System\CurrentControlSet\Control\Session Manager\SubSystems\optional',
        'policy_type'    => 'Registry Values',
        'policy_value'   => '7,Defined: (blank)',
      )
    }
    it {
      is_expected.to contain_local_security_policy('User Account Control: Admin Approval Mode for the Built-in Administrator account').with(
        'ensure'         => 'present',
        'policy_setting' => 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken',
        'policy_type'    => 'Registry Values',
        'policy_value'   => 'enabled',
      )
    }
    it {
      is_expected.to contain_local_security_policy('User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop').with(
        'ensure'         => 'present',
        'policy_setting' => 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle',
        'policy_type'    => 'Registry Values',
        'policy_value'   => 'disabled',
      )
    }
    it {
      is_expected.to contain_local_security_policy('User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode').with(
        'ensure'         => 'present',
        'policy_setting' => 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin',
        'policy_type'    => 'Registry Values',
        'policy_value'   => '4,2',
      )
    }
    it {
      is_expected.to contain_local_security_policy('User Account Control: Behavior of the elevation prompt for standard users').with(
        'ensure'         => 'present',
        'policy_setting' => 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser',
        'policy_type'    => 'Registry Values',
        'policy_value'   => 'disabled',
      )
    }
    it {
      is_expected.to contain_local_security_policy('User Account Control: Detect application installations and prompt for elevation').with(
        'ensure'         => 'present',
        'policy_setting' => 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection',
        'policy_type'    => 'Registry Values',
        'policy_value'   => 'enabled',
      )
    }
    it {
      is_expected.to contain_local_security_policy('User Account Control: Only elevate UIAccess applications that are installed in secure locations').with(
        'ensure'         => 'present',
        'policy_setting' => 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths',
        'policy_type'    => 'Registry Values',
        'policy_value'   => 'enabled',
      )
    }
    it {
      is_expected.to contain_local_security_policy('User Account Control: Run all administrators in Admin Approval Mode').with(
        'ensure'         => 'present',
        'policy_setting' => 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA',
        'policy_type'    => 'Registry Values',
        'policy_value'   => 'enabled',
      )
    }
    it {
      is_expected.to contain_local_security_policy('User Account Control: Switch to the secure desktop when prompting for elevation').with(
        'ensure'         => 'present',
        'policy_setting' => 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop',
        'policy_type'    => 'Registry Values',
        'policy_value'   => 'enabled',
      )
    }
    it {
      is_expected.to contain_local_security_policy('User Account Control: Virtualize file and registry write failures to per-user locations').with(
        'ensure'         => 'present',
        'policy_setting' => 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization',
        'policy_type'    => 'Registry Values',
        'policy_value'   => 'enabled',
      )
    }
    it {
      is_expected.to contain_registry__value('DomainEnableFirewall').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile',
        'value' => 'EnableFirewall',
        'type'  => 'dword',
        'data'  => '0x00000001',
      )
    }
    it {
      is_expected.to contain_registry__value('DomainDefaultInboundAction').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile',
        'value' => 'DefaultInboundAction',
        'type'  => 'dword',
        'data'  => '0x00000001',
      )
    }
    it {
      is_expected.to contain_registry__value('DomainDefaultOutboundAction').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile',
        'value' => 'DefaultOutboundAction',
        'type'  => 'dword',
        'data'  => '0x00000000',
      )
    }
    it {
      is_expected.to contain_registry__value('DomainbDisableNotifications').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile',
        'value' => 'DisableNotifications',
        'type'  => 'dword',
        'data'  => '0x00000001',
      )
    }
    it {
      is_expected.to contain_registry__value('DomainAllowLocalPolicyMerge').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile',
        'value' => 'AllowLocalPolicyMerge',
        'type'  => 'dword',
        'data'  => '0x00000001',
      )
    }
    it {
      is_expected.to contain_registry__value('DomainAllowLocalIPsecPolicyMerge').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile',
        'value' => 'AllowLocalIPsecPolicyMerge',
        'type'  => 'dword',
        'data'  => '0x00000001',
      )
    }
    it {
      is_expected.to contain_registry__value('DomainLogFilePath').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging',
        'value' => 'LogFilePath',
        'type'  => 'string',
        'data'  => '%systemroot%\system32\logfiles\firewall\domainfw.log',
      )
    }
    it {
      is_expected.to contain_registry__value('DomainLogFileSize').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging',
        'value' => 'LogFileSize',
        'type'  => 'dword',
        'data'  => '0x00004000',
      )
    }
    it {
      is_expected.to contain_registry__value('DomainLogDroppedPackets').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging',
        'value' => 'LogDroppedPackets',
        'type'  => 'dword',
        'data'  => '0x00000001',
      )
    }
    it {
      is_expected.to contain_registry__value('DomainLogSuccessfulConnections').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging',
        'value' => 'LogSuccessfulConnections',
        'type'  => 'dword',
        'data'  => '0x00000001',
      )
    }
    it {
      is_expected.to contain_registry__value('PrivateEnableFirewall').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile',
        'value' => 'EnableFirewall',
        'type'  => 'dword',
        'data'  => '0x00000001',
      )
    }
    it {
      is_expected.to contain_registry__value('PrivateDefaultInboundAction').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile',
        'value' => 'DefaultInboundAction',
        'type'  => 'dword',
        'data'  => '0x00000001',
      )
    }
    it {
      is_expected.to contain_registry__value('PrivateDefaultOutboundAction').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile',
        'value' => 'DefaultOutboundAction',
        'type'  => 'dword',
        'data'  => '0x00000000',
      )
    }
    it {
      is_expected.to contain_registry__value('PrivateDisableNotifications').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile',
        'value' => 'DisableNotifications',
        'type'  => 'dword',
        'data'  => '0x00000001',
      )
    }
    it {
      is_expected.to contain_registry__value('PrivateAllowLocalPolicyMerge').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile',
        'value' => 'AllowLocalPolicyMerge',
        'type'  => 'dword',
        'data'  => '0x00000001',
      )
    }
    it {
      is_expected.to contain_registry__value('PrivateAllowLocalIPsecPolicyMerge').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile',
        'value' => 'AllowLocalIPsecPolicyMerge',
        'type'  => 'dword',
        'data'  => '0x00000001',
      )
    }
    it {
      is_expected.to contain_registry__value('PrivateLogFilePath').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging',
        'value' => 'LogFilePath',
        'type'  => 'string',
        'data'  => '%systemroot%\system32\logfiles\firewall\privatefw.log',
      )
    }
    it {
      is_expected.to contain_registry__value('PrivateLogFileSize').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging',
        'value' => 'LogFileSize',
        'type'  => 'dword',
        'data'  => '0x00004000',
      )
    }
    it {
      is_expected.to contain_registry__value('PrivateLogDroppedPackets').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging',
        'value' => 'LogDroppedPackets',
        'type'  => 'dword',
        'data'  => '0x00000001',
      )
    }
    it {
      is_expected.to contain_registry__value('PrivateLogSuccessfulConnections').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging',
        'value' => 'LogSuccessfulConnections',
        'type'  => 'dword',
        'data'  => '0x00000001',
      )
    }
    it {
      is_expected.to contain_registry__value('PublicEnableFirewall').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile',
        'value' => 'EnableFirewall',
        'type'  => 'dword',
        'data'  => '0x00000001',
      )
    }
    it {
      is_expected.to contain_registry__value('PublicDefaultInboundAction').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile',
        'value' => 'DefaultInboundAction',
        'type'  => 'dword',
        'data'  => '0x00000001',
      )
    }
    it {
      is_expected.to contain_registry__value('PublicDefaultOutboundAction').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile',
        'value' => 'DefaultOutboundAction',
        'type'  => 'dword',
        'data'  => '0x00000000',
      )
    }
    it {
      is_expected.to contain_registry__value('PublicDisableNotifications').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile',
        'value' => 'DisableNotifications',
        'type'  => 'dword',
        'data'  => '0x00000000',
      )
    }
    it {
      is_expected.to contain_registry__value('PublicAllowLocalPolicyMerge').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile',
        'value' => 'AllowLocalPolicyMerge',
        'type'  => 'dword',
        'data'  => '0x00000000',
      )
    }
    it {
      is_expected.to contain_registry__value('PublicAllowLocalIPsecPolicyMerge').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile',
        'value' => 'AllowLocalIPsecPolicyMerge',
        'type'  => 'dword',
        'data'  => '0x00000000',
      )
    }
    it {
      is_expected.to contain_registry__value('PublicLogFilePath').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging',
        'value' => 'LogFilePath',
        'type'  => 'string',
        'data'  => '%systemroot%\system32\logfiles\firewall\publicfw.log',
      )
    }
    it {
      is_expected.to contain_registry__value('PublicLogFileSize').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging',
        'value' => 'LogFileSize',
        'type'  => 'dword',
        'data'  => '0x00004000',
      )
    }
    it {
      is_expected.to contain_registry__value('PublicLogDroppedPackets').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging',
        'value' => 'LogDroppedPackets',
        'type'  => 'dword',
        'data'  => '0x00000001',
      )
    }
    it {
      is_expected.to contain_registry__value('PublicLogSuccessfulConnections').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging',
        'value' => 'LogSuccessfulConnections',
        'type'  => 'dword',
        'data'  => '0x00000001',
      )
    }
    it {
      is_expected.to contain_auditpol('Credential Validation').with(
        'success' => 'enable',
        'failure' => 'enable',
      )
    }
    it {
      is_expected.to contain_auditpol('Application Group Management').with(
        'success' => 'enable',
        'failure' => 'enable',
      )
    }
    it {
      is_expected.to contain_auditpol('Computer Account Management').with(
        'success' => 'enable',
        'failure' => 'enable',
      )
    }
    it {
      is_expected.to contain_auditpol('Distribution Group Management').with(
        'success' => 'enable',
        'failure' => 'enable',
      )
    }
    it {
      is_expected.to contain_auditpol('Other Account Management Events').with(
        'success' => 'enable',
        'failure' => 'enable',
      )
    }
    it {
      is_expected.to contain_auditpol('Security Group Management').with(
        'success' => 'enable',
        'failure' => 'enable',
      )
    }
    it {
      is_expected.to contain_auditpol('User Account Management').with(
        'success' => 'enable',
        'failure' => 'enable',
      )
    }
    it {
      is_expected.to contain_auditpol('Process Creation').with(
        'success' => 'enable',
        'failure' => 'disable',
      )
    }
    it {
      is_expected.to contain_auditpol('Directory Service Changes').with(
        'success' => 'enable',
        'failure' => 'enable',
      )
    }
    it {
      is_expected.to contain_auditpol('Directory Service Access').with(
        'success' => 'enable',
        'failure' => 'enable',
      )
    }
    it {
      is_expected.to contain_auditpol('Account Lockout').with(
        'success' => 'enable',
        'failure' => 'disable',
      )
    }
    it {
      is_expected.to contain_auditpol('Logoff').with(
        'success' => 'enable',
        'failure' => 'disable',
      )
    }
    it {
      is_expected.to contain_auditpol('Logon').with(
        'success' => 'enable',
        'failure' => 'enable',
      )
    }
    it {
      is_expected.to contain_auditpol('Other Logon/Logoff Events').with(
        'success' => 'enable',
        'failure' => 'enable',
      )
    }
    it {
      is_expected.to contain_auditpol('Special Logon').with(
        'success' => 'enable',
        'failure' => 'disable',
      )
    }
    it {
      is_expected.to contain_auditpol('Audit Policy Change').with(
        'success' => 'enable',
        'failure' => 'enable',
      )
    }
    it {
      is_expected.to contain_auditpol('Authentication Policy Change').with(
        'success' => 'enable',
        'failure' => 'disable',
      )
    }
    it {
      is_expected.to contain_auditpol('Sensitive Privilege Use').with(
        'success' => 'enable',
        'failure' => 'enable',
      )
    }
    it {
      is_expected.to contain_auditpol('IPsec Driver').with(
        'success' => 'enable',
        'failure' => 'enable',
      )
    }
    it {
      is_expected.to contain_auditpol('Other System Events').with(
        'success' => 'enable',
        'failure' => 'enable',
      )
    }
    it {
      is_expected.to contain_auditpol('Security State Change').with(
        'success' => 'enable',
        'failure' => 'disable',
      )
    }
    it {
      is_expected.to contain_auditpol('Security System Extension').with(
        'success' => 'enable',
        'failure' => 'enable',
      )
    }
    it {
      is_expected.to contain_auditpol('System Integrity').with(
        'success' => 'enable',
        'failure' => 'enable',
      )
    }
    # L2
    # it {
    #   should contain_registry__value('AllowLLTDIOOnDomain').with(
    #     'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LLTD',
    #     'value' => 'AllowLLTDIOOnDomain',
    #     'type'  => 'dword',
    #     'data'  => '0x00000000'
    #   )
    # }
    # it {
    #   should contain_registry__value('AllowLLTDIOOnPublicNet').with(
    #     'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LLTD',
    #     'value' => 'AllowLLTDIOOnPublicNet',
    #     'type'  => 'dword',
    #     'data'  => '0x00000000'
    #   )
    # }
    # it {
    #   should contain_registry__value('EnableLLTDIO').with(
    #     'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LLTD',
    #     'value' => 'EnableLLTDIO',
    #     'type'  => 'dword',
    #     'data'  => '0x00000000'
    #   )
    # }
    # it {
    #   should contain_registry__value('ProhibitLLTDIOOnPrivateNet').with(
    #     'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LLTD',
    #     'value' => 'ProhibitLLTDIOOnPrivateNet',
    #     'type'  => 'dword',
    #     'data'  => '0x00000000'
    #   )
    # }
    # it {
    #   should contain_registry__value('AllowRspndrOnDomain').with(
    #     'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LLTD',
    #     'value' => 'AllowRspndrOnDomain',
    #     'type'  => 'dword',
    #     'data'  => '0x00000000'
    #   )
    # }
    # it {
    #   should contain_registry__value('AllowRspndrOnPublicNet').with(
    #     'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LLTD',
    #     'value' => 'AllowRspndrOnPublicNet',
    #     'type'  => 'dword',
    #     'data'  => '0x00000000'
    #   )
    # }
    # it {
    #   should contain_registry__value('EnableRspndr').with(
    #     'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LLTD',
    #     'value' => 'EnableRspndr',
    #     'type'  => 'dword',
    #     'data'  => '0x00000000'
    #   )
    # }
    # it {
    #   should contain_registry__value('ProhibitRspndrOnPrivateNet').with(
    #     'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LLTD',
    #     'value' => 'ProhibitRspndrOnPrivateNet',
    #     'type'  => 'dword',
    #     'data'  => '0x00000000'
    #   )
    # }
    # it {
    #   should contain_registry__value('PeernetDisabled').with(
    #     'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Peernet',
    #     'value' => 'Disabled',
    #     'type'  => 'dword',
    #     'data'  => '0x00000001'
    #   )
    # }
    it {
      is_expected.to contain_registry__value('NC_AllowNetBridge_NLA').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Network Connections',
        'value' => 'NC_AllowNetBridge_NLA',
        'type'  => 'dword',
        'data'  => '0x00000000',
      )
    }
    it {
      is_expected.to contain_registry__value('NC_StdDomainUserSetLocation').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Network Connections',
        'value' => 'NC_StdDomainUserSetLocation',
        'type'  => 'dword',
        'data'  => '0x00000001',
      )
    }
    # it {
    #   should contain_registry__value('EnableRegistrars').with(
    #     'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars',
    #     'value' => 'EnableRegistrars',
    #     'type'  => 'dword',
    #     'data'  => '0x00000000'
    #   )
    # }
    # it {
    #   should contain_registry__value('DisableWPDRegistrar').with(
    #     'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars',
    #     'value' => 'DisableWPDRegistrar',
    #     'type'  => 'dword',
    #     'data'  => '0x00000000'
    #   )
    # }
    # it {
    #   should contain_registry__value('DisableUPnPRegistrar').with(
    #     'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars',
    #     'value' => 'DisableUPnPRegistrar',
    #     'type'  => 'dword',
    #     'data'  => '0x00000000'
    #   )
    # }
    # it {
    #   should contain_registry__value('DisableInBand802DOT11Registrar').with(
    #     'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars',
    #     'value' => 'DisableInBand802DOT11Registrar',
    #     'type'  => 'dword',
    #     'data'  => '0x00000000'
    #   )
    # }
    # it {
    #   should contain_registry__value('DisableFlashConfigRegistrar').with(
    #     'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars',
    #     'value' => 'DisableFlashConfigRegistrar',
    #     'type'  => 'dword',
    #     'data'  => '0x00000000'
    #   )
    # }
    # it {
    #   should contain_registry__value('DisableWcnUi').with(
    #     'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WCN\UI',
    #     'value' => 'DisableWcnUi',
    #     'type'  => 'dword',
    #     'data'  => '0x00000001'
    #   )
    # }
    it {
      is_expected.to contain_registry__value('AllowRemoteRPC').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Settings',
        'value' => 'AllowRemoteRPC',
        'type'  => 'dword',
        'data'  => '0x00000000',
      )
    }
    it {
      is_expected.to contain_registry__value('NoBackgroundPolicy').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}',
        'value' => 'NoBackgroundPolicy',
        'type'  => 'dword',
        'data'  => '0x00000000',
      )
    }
    it {
      is_expected.to contain_registry__value('NoGPOListChange').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}',
        'value' => 'NoGPOListChange',
        'type'  => 'dword',
        'data'  => '0x00000000',
      )
    }
    # MS
    # it {
    #   should contain_registry__value('LogonType').with(
    #     'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System',
    #     'value' => 'LogonType',
    #     'type'  => 'dword',
    #     'data'  => '0x00000000'
    #   )
    # }
    it {
      is_expected.to contain_registry__value('fAllowUnsolicited').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services',
        'value' => 'fAllowUnsolicited',
        'type'  => 'dword',
        'data'  => '0x00000000',
      )
    }
    it {
      is_expected.to contain_registry__value('fAllowToGetHelp').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services',
        'value' => 'fAllowToGetHelp',
        'type'  => 'dword',
        'data'  => '0x00000000',
      )
    }
    # MS
    # it {
    #   should contain_registry__value('EnableAuthEpResolution').with(
    #     'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Rpc',
    #     'value' => 'EnableAuthEpResolution',
    #     'type'  => 'dword',
    #     'data'  => '0x00000001'
    #   )
    # }
    it {
      is_expected.to contain_registry__value('NoAutoplayfornonVolume').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer',
        'value' => 'NoAutoplayfornonVolume',
        'type'  => 'dword',
        'data'  => '0x00000001',
      )
    }
    it {
      is_expected.to contain_registry__value('NoAutorun').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer',
        'value' => 'NoAutorun',
        'type'  => 'dword',
        'data'  => '0x00000001',
      )
    }
    it {
      is_expected.to contain_registry__value('NoDriveTypeAutoRun').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer',
        'value' => 'NoDriveTypeAutoRun',
        'type'  => 'dword',
        'data'  => '0x000000ff',
      )
    }
    it {
      is_expected.to contain_registry__value('EnumerateAdministrators').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI',
        'value' => 'EnumerateAdministrators',
        'type'  => 'dword',
        'data'  => '0x00000000',
      )
    }
    it {
      is_expected.to contain_registry__value('TurnOffSidebar').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Windows\Sidebar',
        'value' => 'TurnOffSidebar',
        'type'  => 'dword',
        'data'  => '0x00000001',
      )
    }
    it {
      is_expected.to contain_registry__value('TurnOffUserInstalledGadgets').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Windows\Sidebar',
        'value' => 'TurnOffUserInstalledGadgets',
        'type'  => 'dword',
        'data'  => '0x00000001',
      )
    }
    it {
      is_expected.to contain_registry__value('ApplicationRetention').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application',
        'value' => 'Retention',
        'type'  => 'string',
        'data'  => '0',
      )
    }
    it {
      is_expected.to contain_registry__value('ApplicationMaxSize').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application',
        'value' => 'MaxSize',
        'type'  => 'dword',
        'data'  => '0x00008000',
      )
    }
    it {
      is_expected.to contain_registry__value('SecurityRetention').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security',
        'value' => 'Retention',
        'type'  => 'string',
        'data'  => '0',
      )
    }
    it {
      is_expected.to contain_registry__value('SecurityMaxSize').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security',
        'value' => 'MaxSize',
        'type'  => 'dword',
        'data'  => '0x00030000',
      )
    }
    it {
      is_expected.to contain_registry__value('SetupRetention').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup',
        'value' => 'Retention',
        'type'  => 'string',
        'data'  => '0',
      )
    }
    it {
      is_expected.to contain_registry__value('SetupMaxSize').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup',
        'value' => 'MaxSize',
        'type'  => 'dword',
        'data'  => '0x00008000',
      )
    }
    it {
      is_expected.to contain_registry__value('SystemRetention').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\System',
        'value' => 'Retention',
        'type'  => 'string',
        'data'  => '0',
      )
    }
    it {
      is_expected.to contain_registry__value('SystemMaxSize').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\System',
        'value' => 'MaxSize',
        'type'  => 'dword',
        'data'  => '0x00008000',
      )
    }
    it {
      is_expected.to contain_registry__value('NoDataExecutionPrevention').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer',
        'value' => 'NoDataExecutionPrevention',
        'type'  => 'dword',
        'data'  => '0x00000000',
      )
    }
    it {
      is_expected.to contain_registry__value('NoHeapTerminationOnCorruption').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer',
        'value' => 'NoHeapTerminationOnCorruption',
        'type'  => 'dword',
        'data'  => '0x00000000',
      )
    }
    it {
      is_expected.to contain_registry__value('PreXPSP2ShellProtocolBehavior').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer',
        'value' => 'PreXPSP2ShellProtocolBehavior',
        'type'  => 'dword',
        'data'  => '0x00000000',
      )
    }
    # level 2
    # it {
    #   should contain_registry__value('DisableLocation').with(
    #     'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors',
    #     'value' => 'DisableLocation',
    #     'type'  => 'dword',
    #     'data'  => '0x00000001'
    #   )
    # }
    it {
      is_expected.to contain_registry__value('DisablePasswordSaving').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services',
        'value' => 'DisablePasswordSaving',
        'type'  => 'dword',
        'data'  => '0x00000001',
      )
    }
    # it {
    #   should contain_registry__value('fSingleSessionPerUser').with(
    #     'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services',
    #     'value' => 'fSingleSessionPerUser',
    #     'type'  => 'dword',
    #     'data'  => '0x00000001'
    #   )
    # }
    # it {
    #   should contain_registry__value('fDisableCcm').with(
    #     'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services',
    #     'value' => 'fDisableCcm',
    #     'type'  => 'dword',
    #     'data'  => '0x00000001'
    #   )
    # }
    it {
      is_expected.to contain_registry__value('fDisableCdm').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services',
        'value' => 'fDisableCdm',
        'type'  => 'dword',
        'data'  => '0x00000001',
      )
    }
    # level 2
    # it {
    #   should contain_registry__value('fDisableLPT').with(
    #     'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services',
    #     'value' => 'fDisableLPT',
    #     'type'  => 'dword',
    #     'data'  => '0x00000001'
    #   )
    # # }
    # it {
    #   should contain_registry__value('fDisablePNPRedir').with(
    #     'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services',
    #     'value' => 'fDisablePNPRedir',
    #     'type'  => 'dword',
    #     'data'  => '0x00000001'
    #   )
    # }
    it {
      is_expected.to contain_registry__value('fPromptForPassword').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services',
        'value' => 'fPromptForPassword',
        'type'  => 'dword',
        'data'  => '0x00000001',
      )
    }
    it {
      is_expected.to contain_registry__value('fEncryptRPCTraffic').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services',
        'value' => 'fEncryptRPCTraffic',
        'type'  => 'dword',
        'data'  => '0x00000001',
      )
    }
    it {
      is_expected.to contain_registry__value('MinEncryptionLevel').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services',
        'value' => 'MinEncryptionLevel',
        'type'  => 'dword',
        'data'  => '0x00000003',
      )
    }
    # level 2
    # it {
    #   should contain_registry__value('MaxIdleTime').with(
    #     'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services',
    #     'value' => 'MaxIdleTime',
    #     'type'  => 'dword',
    #     'data'  => '0x000dbba0'
    #   )
    # }
    # it {
    #   should contain_registry__value('MaxDisconnectionTime').with(
    #     'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services',
    #     'value' => 'MaxDisconnectionTime',
    #     'type'  => 'dword',
    #     'data'  => '0x0000ea60'
    #   )
    # }
    it {
      is_expected.to contain_registry__value('DeleteTempDirsOnExit').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services',
        'value' => 'DeleteTempDirsOnExit',
        'type'  => 'dword',
        'data'  => '0x00000001',
      )
    }
    it {
      is_expected.to contain_registry__value('PerSessionTempDir').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services',
        'value' => 'PerSessionTempDir',
        'type'  => 'dword',
        'data'  => '0x00000001',
      )
    }
    it {
      is_expected.to contain_registry__value('DisableEnclosureDownload').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds',
        'value' => 'DisableEnclosureDownload',
        'type'  => 'dword',
        'data'  => '0x00000001',
      )
    }
    it {
      is_expected.to contain_registry__value('DefaultConsent').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting\Consent',
        'value' => 'DefaultConsent',
        'type'  => 'dword',
        'data'  => '0x00000001',
      )
    }
    it {
      is_expected.to contain_registry__value('EnableUserControl').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer',
        'value' => 'EnableUserControl',
        'type'  => 'dword',
        'data'  => '0x00000000',
      )
    }
    it {
      is_expected.to contain_registry__value('AlwaysInstallElevated').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer',
        'value' => 'AlwaysInstallElevated',
        'type'  => 'dword',
        'data'  => '0x00000000',
      )
    }
    it {
      is_expected.to contain_registry__value('ClientAllowBasic').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client',
        'value' => 'AllowBasic',
        'type'  => 'dword',
        'data'  => '0x00000000',
      )
    }
    it {
      is_expected.to contain_registry__value('ClientAllowUnencryptedTraffic').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client',
        'value' => 'AllowUnencryptedTraffic',
        'type'  => 'dword',
        'data'  => '0x00000000',
      )
    }
    it {
      is_expected.to contain_registry__value('AllowDigest').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client',
        'value' => 'AllowDigest',
        'type'  => 'dword',
        'data'  => '0x00000000',
      )
    }
    it {
      is_expected.to contain_registry__value('ServiceAllowBasic').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service',
        'value' => 'AllowBasic',
        'type'  => 'dword',
        'data'  => '0x00000000',
      )
    }
    it {
      is_expected.to contain_registry__value('ServiceAllowUnencryptedTraffic').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service',
        'value' => 'AllowUnencryptedTraffic',
        'type'  => 'dword',
        'data'  => '0x00000000',
      )
    }
    # level 2
    # it {
    #   should contain_registry__value('AllowRemoteShellAccess').with(
    #     'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\WinRS',
    #     'value' => 'AllowRemoteShellAccess',
    #     'type'  => 'dword',
    #     'data'  => '0x00000000'
    #   )
    # }
    it {
      is_expected.to contain_registry__value('NoAutoUpdate').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU',
        'value' => 'NoAutoUpdate',
        'type'  => 'dword',
        'data'  => '0x00000000',
      )
    }
    it {
      is_expected.to contain_registry__value('ScheduledInstallDay').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU',
        'value' => 'ScheduledInstallDay',
        'type'  => 'dword',
        'data'  => '0x00000000',
      )
    }
    it {
      is_expected.to contain_registry__value('NoAUAsDefaultShutdownOption').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU',
        'value' => 'NoAUAsDefaultShutdownOption',
        'type'  => 'dword',
        'data'  => '0x00000000',
      )
    }
    it {
      is_expected.to contain_registry__value('NoAUShutdownOption').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU',
        'value' => 'NoAUShutdownOption',
        'type'  => 'dword',
        'data'  => '0x00000000',
      )
    }
    it {
      is_expected.to contain_registry__value('NoAutoRebootWithLoggedOnUsers').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU',
        'value' => 'NoAutoRebootWithLoggedOnUsers',
        'type'  => 'dword',
        'data'  => '0x00000000',
      )
    }
    it {
      is_expected.to contain_registry__value('RescheduleWaitTimeEnabled').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU',
        'value' => 'RescheduleWaitTimeEnabled',
        'type'  => 'dword',
        'data'  => '0x00000001',
      )
    }
    it {
      is_expected.to contain_registry__value('RescheduleWaitTime').with(
        'key'   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU',
        'value' => 'RescheduleWaitTime',
        'type'  => 'dword',
        'data'  => '0x00000001',
      )
    }
  end
  # context 'Member Server Level 2' do
  # end
  # context 'Domain Controller Level 2' do
  # end
end
