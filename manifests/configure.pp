# Configuration Settings for Windows Servers
class harden_windows_server::configure {
  class { '::local_security_policy': }

  if($harden_windows_server::ensure_enforce_password_history_is_set_to_24_or_more_passwords) {
    local_security_policy { 'Enforce password history':
      ensure         => 'present',
      policy_setting => 'PasswordHistorySize',
      policy_type    => 'System Access',
      policy_value   => '24',
    }
  }

  if($harden_windows_server::ensure_maximum_password_age_is_set_to_60_or_fewer_days_but_not_0) {
    local_security_policy { 'Maximum password age':
      ensure         => 'present',
      policy_setting => 'MaximumPasswordAge',
      policy_type    => 'System Access',
      policy_value   => '42',
    }
  }

  if($harden_windows_server::ensure_minimum_password_age_is_set_to_1_or_more_days) {
    local_security_policy { 'Minimum password age':
      ensure         => 'present',
      policy_setting => 'MinimumPasswordAge',
      policy_type    => 'System Access',
      policy_value   => '1',
    }
  }

  if($harden_windows_server::ensure_minimum_password_length_is_set_to_14_or_more_characters) {
    local_security_policy { 'Minimum password length':
      ensure         => 'present',
      policy_setting => 'MinimumPasswordLength',
      policy_type    => 'System Access',
      policy_value   => '14',
    }
  }

  if($harden_windows_server::ensure_password_must_meet_complexity_requirements_is_set_to_enabled) {
    local_security_policy { 'Password must meet complexity requirements':
      ensure         => 'present',
      policy_setting => 'PasswordComplexity',
      policy_type    => 'System Access',
      policy_value   => '1',
    }
  }

  if($harden_windows_server::ensure_store_passwords_using_reversible_encryption_is_set_to_disabled) {
    local_security_policy { 'Store passwords using reversible encryption':
      ensure         => 'present',
      policy_setting => 'ClearTextPassword',
      policy_type    => 'System Access',
      policy_value   => '0',
    }
  }

  if($harden_windows_server::ensure_account_lockout_duration_is_set_to_15_or_more_minutes) {
    local_security_policy { 'Account lockout duration':
      ensure         => 'present',
      policy_setting => 'LockoutDuration',
      policy_type    => 'System Access',
      policy_value   => '30',
    }
  }

  if($harden_windows_server::ensure_account_lockout_threshold_is_set_to_10_or_fewer_invalid_logon_attempts_but_not_0) {
    local_security_policy { 'Account lockout threshold':
      ensure         => 'present',
      policy_setting => 'LockoutBadCount',
      policy_type    => 'System Access',
      policy_value   => '10',
    }
  }

  if($harden_windows_server::ensure_reset_account_lockout_counter_after_is_set_to_15_or_more_minutes) {
    local_security_policy { 'Reset account lockout counter after':
      ensure         => 'present',
      policy_setting => 'ResetLockoutCount',
      policy_type    => 'System Access',
      policy_value   => '30',
    }
  }

  if($harden_windows_server::ensure_access_credential_manager_as_a_trusted_caller_is_set_to_no_one) {
    local_security_policy { 'Access Credential Manager as a trusted caller':
      ensure         => 'absent',
    }
  }

  if($harden_windows_server::configure_access_this_computer_from_the_network) {
    if($harden_windows_server::is_domain_controller) {
      local_security_policy { 'Access this computer from the network':
        ensure         => 'present',
        policy_setting => 'SeNetworkLogonRight',
        policy_type    => 'Privilege Rights',
        policy_value   => '*S-1-5-32-544,*S-1-5-11,*S-1-5-9',
      }
    } else {
      local_security_policy { 'Access this computer from the network':
        ensure         => 'present',
        policy_setting => 'SeNetworkLogonRight',
        policy_type    => 'Privilege Rights',
        policy_value   => '*S-1-5-32-544,*S-1-5-11',
      }
    }
  }

  if($harden_windows_server::ensure_act_as_part_of_the_operating_system_is_set_to_no_one) {
    local_security_policy { 'Act as part of the operating system':
      ensure         => 'absent',
    }
  }

  if($harden_windows_server::ensure_add_workstations_to_domain_is_set_to_administrators) {
    if($harden_windows_server::is_domain_controller) {
      local_security_policy { 'Add workstations to domain':
        ensure         => 'present',
        policy_setting => 'SeMachineAccountPrivilege',
        policy_type    => 'Privilege Rights',
        policy_value   => '*S-1-5-32-544',
      }
    }
  }

  if($harden_windows_server::ensure_adjust_memory_quotas_for_a_process_is_set_to_administrators_local_service_network_service) {
    local_security_policy { 'Adjust memory quotas for a process':
      ensure         => 'present',
      policy_setting => 'SeIncreaseQuotaPrivilege',
      policy_type    => 'Privilege Rights',
      policy_value   => '*S-1-5-19,*S-1-5-20,*S-1-5-32-544',
    }
  }

  if($harden_windows_server::configure_allow_log_on_locally) {
    if($harden_windows_server::is_domain_controller) {
      local_security_policy { 'Allow log on locally':
        ensure         => 'present',
        policy_setting => 'SeInteractiveLogonRight',
        policy_type    => 'Privilege Rights',
        policy_value   => '*S-1-5-32-544,*S-1-5-9',
      }
    } else {
      local_security_policy { 'Allow log on locally':
        ensure         => 'present',
        policy_setting => 'SeInteractiveLogonRight',
        policy_type    => 'Privilege Rights',
        policy_value   => '*S-1-5-32-544',
      }
    }
  }

  if($harden_windows_server::configure_allow_log_on_through_remote_desktop_services) {
    if($harden_windows_server::is_domain_controller) {
      local_security_policy { 'Allow log on through Remote Desktop Services':
        ensure         => 'present',
        policy_setting => 'SeRemoteInteractiveLogonRight',
        policy_type    => 'Privilege Rights',
        policy_value   => '*S-1-5-32-544',
      }
    } else {
      local_security_policy { 'Allow log on through Remote Desktop Services':
        ensure         => 'present',
        policy_setting => 'SeRemoteInteractiveLogonRight',
        policy_type    => 'Privilege Rights',
        policy_value   => '*S-1-5-32-544,*S-1-5-32-555',
      }
    }
  }

  if($harden_windows_server::ensure_back_up_files_and_directories_is_set_to_administrators) {
    local_security_policy { 'Back up files and directories':
      ensure         => 'present',
      policy_setting => 'SeBackupPrivilege',
      policy_type    => 'Privilege Rights',
      policy_value   => '*S-1-5-32-544',
    }
  }

  if($harden_windows_server::ensure_change_the_system_time_is_set_to_administrators_local_service) {
    local_security_policy { 'Change the system time':
      ensure         => 'present',
      policy_setting => 'SeSystemtimePrivilege',
      policy_type    => 'Privilege Rights',
      policy_value   => '*S-1-5-19,*S-1-5-32-544',
    }
  }

  if($harden_windows_server::ensure_change_the_time_zone_is_set_to_administrators_local_service) {
    local_security_policy { 'Change the time zone':
      ensure         => 'present',
      policy_setting => 'SeTimeZonePrivilege',
      policy_type    => 'Privilege Rights',
      policy_value   => '*S-1-5-19,*S-1-5-32-544',
    }
  }

  if($harden_windows_server::ensure_create_a_pagefile_is_set_to_administrators) {
    local_security_policy { 'Create a pagefile':
      ensure         => 'present',
      policy_setting => 'SeCreatePagefilePrivilege',
      policy_type    => 'Privilege Rights',
      policy_value   => '*S-1-5-32-544',
    }
  }

  if($harden_windows_server::ensure_create_a_token_object_is_set_to_no_one) {
    local_security_policy { 'Create a token object':
      ensure         => 'absent',
    }
  }

  if($harden_windows_server::ensure_create_global_objects_is_set_to_administrators_local_service_network_service_service) {
    local_security_policy { 'Create global objects':
      ensure         => 'present',
      policy_setting => 'SeCreateGlobalPrivilege',
      policy_type    => 'Privilege Rights',
      policy_value   => '*S-1-5-19,*S-1-5-20,*S-1-5-32-544,*S-1-5-6',
    }
  }

  if($harden_windows_server::ensure_create_permanent_shared_objects_is_set_to_no_one) {
    local_security_policy { 'Create permanent shared objects':
      ensure         => 'absent',
    }
  }

  #only need S-1-85-0 if Hyper-V role is activated, not sure how to handle this
  if($harden_windows_server::configure_create_symbolic_links) {
    if($harden_windows_server::is_domain_controller) {
      local_security_policy { 'Create symbolic links':
        ensure         => 'present',
        policy_setting => 'SeCreateSymbolicLinkPrivilege',
        policy_type    => 'Privilege Rights',
        policy_value   => '*S-1-5-32-544',
      }
    } else {
      local_security_policy { 'Create symbolic links':
        ensure         => 'present',
        policy_setting => 'SeCreateSymbolicLinkPrivilege',
        policy_type    => 'Privilege Rights',
        policy_value   => '*S-1-5-32-544,*S-1-5-83-0',
      }
    }
  }

  if($harden_windows_server::ensure_debug_programs_is_set_to_administrators) {
    local_security_policy { 'Debug programs':
      ensure         => 'present',
      policy_setting => 'SeDebugPrivilege',
      policy_type    => 'Privilege Rights',
      policy_value   => '*S-1-5-32-544',
    }
  }

  if($harden_windows_server::configure_deny_access_to_this_computer_from_the_network) {
    if($harden_windows_server::is_domain_controller) {
      local_security_policy { 'Deny access to this computer from the network':
        ensure         => 'present',
        policy_setting => 'SeDenyNetworkLogonRight',
        policy_type    => 'Privilege Rights',
        policy_value   => '*S-1-5-32-546,*S-1-2-0',
      }
    } else {
      local_security_policy { 'Deny access to this computer from the network':
        ensure         => 'present',
        policy_setting => 'SeDenyNetworkLogonRight',
        policy_type    => 'Privilege Rights',
        policy_value   => '*S-1-5-32-546,*S-1-2-0,*S-1-5-32-544',
      }
    }
  }

  if($harden_windows_server::ensure_deny_log_on_as_a_batch_job_to_include_guests) {
    local_security_policy { 'Deny log on as a batch job':
      ensure         => 'present',
      policy_setting => 'SeDenyBatchLogonRight',
      policy_type    => 'Privilege Rights',
      policy_value   => '*S-1-5-32-546',
    }
  }

  if($harden_windows_server::ensure_deny_log_on_as_a_service_to_include_guests) {
    local_security_policy { 'Deny log on as a service':
      ensure         => 'present',
      policy_setting => 'SeDenyServiceLogonRight',
      policy_type    => 'Privilege Rights',
      policy_value   => '*S-1-5-32-546',
    }
  }

  if($harden_windows_server::ensure_deny_log_on_locally_to_include_guests) {
    local_security_policy { 'Deny log on locally':
      ensure         => 'present',
      policy_setting => 'SeDenyInteractiveLogonRight',
      policy_type    => 'Privilege Rights',
      policy_value   => '*S-1-5-32-546',
    }
  }

  if($harden_windows_server::ensure_deny_log_on_through_remote_desktop_services_to_include_guests_local_account) {
    local_security_policy { 'Deny log on through Remote Desktop Services':
      ensure         => 'present',
      policy_setting => 'SeDenyRemoteInteractiveLogonRight',
      policy_type    => 'Privilege Rights',
      policy_value   => '*S-1-5-32-546,*S-1-2-0',
    }
  }

  if($harden_windows_server::configure_enable_computer_and_user_acounts_to_be_trusted_for_delegation) {
    if($harden_windows_server::is_domain_controller) {
      local_security_policy { 'Enable computer and user accounts to be trusted for delegation':
        ensure         => 'present',
        policy_setting => 'SeEnableDelegationPrivilege',
        policy_type    => 'Privilege Rights',
        policy_value   => '*S-1-5-32-544',
      }
    } else {
      local_security_policy { 'Enable computer and user accounts to be trusted for delegation':
        ensure         => 'absent',
      }
    }
  }

  if($harden_windows_server::ensure_force_shutdown_from_a_remote_system_is_set_to_administrators) {
    local_security_policy { 'Force shutdown from a remote system':
      ensure         => 'present',
      policy_setting => 'SeRemoteShutdownPrivilege',
      policy_type    => 'Privilege Rights',
      policy_value   => '*S-1-5-32-544',
    }
  }

  if($harden_windows_server::ensure_generate_security_audits_is_set_to_local_service_network_service) {
    local_security_policy { 'Generate security audits':
      ensure         => 'present',
      policy_setting => 'SeAuditPrivilege',
      policy_type    => 'Privilege Rights',
      policy_value   => '*S-1-5-19,*S-1-5-20',
    }
  }

  #S-1-5-17 is only used when the Web Server (IIS) role is activated for MS
  if($harden_windows_server::configure_impersonate_a_client_after_authentication) {
    if($harden_windows_server::is_domain_controller) {
      local_security_policy { 'Impersonate a client after authentication':
        ensure         => 'present',
        policy_setting => 'SeImpersonatePrivilege',
        policy_type    => 'Privilege Rights',
        policy_value   => '*S-1-5-19,*S-1-5-20,*S-1-5-32-544,*S-1-5-6',
      }
    } else {
      local_security_policy { 'Impersonate a client after authentication':
        ensure         => 'present',
        policy_setting => 'SeImpersonatePrivilege',
        policy_type    => 'Privilege Rights',
        policy_value   => '*S-1-5-19,*S-1-5-20,*S-1-5-32-544,*S-1-5-6',
      }
    }
  }

  if($harden_windows_server::ensure_increase_scheduling_priority_is_set_to_administrators) {
    local_security_policy { 'Increase scheduling priority':
      ensure         => 'present',
      policy_setting => 'SeIncreaseBasePriorityPrivilege',
      policy_type    => 'Privilege Rights',
      policy_value   => '*S-1-5-32-544',
    }
  }

  if($harden_windows_server::ensure_load_and_unload_device_drivers_is_set_to_administrators) {
    local_security_policy { 'Load and unload device drivers':
      ensure         => 'present',
      policy_setting => 'SeLoadDriverPrivilege',
      policy_type    => 'Privilege Rights',
      policy_value   => '*S-1-5-32-544',
    }
  }

  if($harden_windows_server::ensure_lock_pages_in_menory_is_set_to_no_one) {
    local_security_policy { 'Lock pages in memory':
      ensure         => 'absent',
    }
  }

  #LEVEL 2, DC ONLY
  if($harden_windows_server::ensure_log_on_as_a_batch_job_is_set_to_administrators) {
    if($harden_windows_server::is_domain_controller) {
      local_security_policy { 'Log on as a batch job':
        ensure         => 'present',
        policy_setting => 'SeBatchLogonRight',
        policy_type    => 'Privilege Rights',
        policy_value   => '*S-1-5-32-544,*S-1-5-32-551,*S-1-5-32-559',
      }
    }
  }

  #DCs also need Exchange Servers when Exchange is running, not sure how to handle
  if($harden_windows_server::configure_manage_auditing_and_security_log) {
    if($harden_windows_server::is_domain_controller) {
      local_security_policy { 'Manage auditing and security log':
        ensure         => 'present',
        policy_setting => 'SeSecurityPrivilege',
        policy_type    => 'Privilege Rights',
        policy_value   => '*S-1-5-32-544',
      }
    } else {
      local_security_policy { 'Manage auditing and security log':
        ensure         => 'present',
        policy_setting => 'SeSecurityPrivilege',
        policy_type    => 'Privilege Rights',
        policy_value   => '*S-1-5-32-544',
      }
    }
  }

  if($harden_windows_server::ensure_modify_an_object_label_is_set_to_no_one) {
    local_security_policy { 'Modify an object label':
      ensure         => 'absent',
    }
  }

  if($harden_windows_server::ensure_modify_firmware_environment_values_is_set_to_administrators) {
    local_security_policy { 'Modify firmware environment values':
      ensure         => 'present',
      policy_setting => 'SeSystemEnvironmentPrivilege',
      policy_type    => 'Privilege Rights',
      policy_value   => '*S-1-5-32-544',
    }
  }

  if($harden_windows_server::ensure_perform_volume_maintenance_tasks_is_set_to_administrators) {
    local_security_policy { 'Perform volume maintenance tasks':
      ensure         => 'present',
      policy_setting => 'SeManageVolumePrivilege',
      policy_type    => 'Privilege Rights',
      policy_value   => '*S-1-5-32-544',
    }
  }

  if($harden_windows_server::ensure_profile_single_process_is_set_to_administrators) {
    local_security_policy { 'Profile single process':
      ensure         => 'present',
      policy_setting => 'SeProfileSingleProcessPrivilege',
      policy_type    => 'Privilege Rights',
      policy_value   => '*S-1-5-32-544',
    }
  }

  if($harden_windows_server::ensure_profile_system_performance_is_set_to_administrators_nt_service_wdiservicehost) {
    local_security_policy { 'Profile system performance':
      ensure         => 'present',
      policy_setting => 'SeSystemProfilePrivilege',
      policy_type    => 'Privilege Rights',
      policy_value   => '*S-1-5-32-544,*S-1-5-80-3139157870-2983391045-3678747466-658725712-1809340420',
    }
  }

  if($harden_windows_server::ensure_replace_a_process_level_token_is_set_to_local_service_network_service) {
    local_security_policy { 'Replace a process level token':
      ensure         => 'present',
      policy_setting => 'SeAssignPrimaryTokenPrivilege',
      policy_type    => 'Privilege Rights',
      policy_value   => '*S-1-5-19,*S-1-5-20',
    }
  }

  if($harden_windows_server::ensure_restore_files_and_directories_is_set_to_administrators) {
    local_security_policy { 'Restore files and directories':
      ensure         => 'present',
      policy_setting => 'SeRestorePrivilege',
      policy_type    => 'Privilege Rights',
      policy_value   => '*S-1-5-32-544',
    }
  }

  if($harden_windows_server::ensure_shut_down_the_system_is_set_to_administrators) {
    local_security_policy { 'Shut down the system':
      ensure         => 'present',
      policy_setting => 'SeShutdownPrivilege',
      policy_type    => 'Privilege Rights',
      policy_value   => '*S-1-5-32-544',
    }
  }

  if($harden_windows_server::ensure_synchronize_directory_service_data_is_set_to_no_one) {
    if($harden_windows_server::is_domain_controller) {
      local_security_policy { 'Synchronize directory service data':
        ensure         => 'absent',
      }
    }
  }

  if($harden_windows_server::ensure_take_ownership_of_files_or_other_objects_is_set_to_administrators) {
    local_security_policy { 'Take ownership of files or other objects':
      ensure         => 'present',
      policy_setting => 'SeTakeOwnershipPrivilege',
      policy_type    => 'Privilege Rights',
      policy_value   => '*S-1-5-32-544',
    }
  }

  #Not supported by local_security_policy and no registry key
  #if($harden_windows_server::ensure_accounts_administrator_account_status_is_set_to_disabled) {

  #}

  #if($harden_windows_server::ensure_accounts_guest_account_status_is_set_to_disabled) {

  #}

  if($harden_windows_server::ensure_accounts_limit_local_account_use_of_blank_password_to_console_logon_only_is_set_to_enabled) {
    local_security_policy { 'Accounts: Limit local account use of blank passwords to console logon only':
      ensure         => 'present',
      policy_setting => 'MACHINE\System\CurrentControlSet\Control\Lsa\LimitBlankPasswordUse',
      policy_type    => 'Registry Values',
      policy_value   => '4,1',
    }
  }

  if($harden_windows_server::configure_accounts_rename_administrator_account) {
    local_security_policy { 'Accounts: Rename administrator account':
      ensure         => 'present',
      policy_setting => 'NewAdministratorName',
      policy_type    => 'System Access',
      policy_value   => '"adminaccount"',
    }
  }

  if($harden_windows_server::configure_accounts_rename_guest_account) {
    local_security_policy { 'Accounts: Rename guest account':
      ensure         => 'present',
      policy_setting => 'NewGuestName',
      policy_type    => 'System Access',
      policy_value   => '"guestaccount"',
    }
  }

  if($harden_windows_server::ensure_audit_force_audit_policy_subcategory_settings_to_override_audit_policy_category_settings) {
    $title2321 = 'Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings'
    local_security_policy { $title2321:
      ensure         => 'present',
      policy_setting => 'MACHINE\System\CurrentControlSet\Control\Lsa\SCENoApplyLegacyAuditPolicy',
      policy_type    => 'Registry Values',
      policy_value   => '4,1',
    }
  }

  if($harden_windows_server::ensure_audit_shut_down_system_immediately_if_unable_to_log_security_audits_is_set_to_disabled) {
    local_security_policy { 'Audit: Shut down system immediately if unable to log security audits':
      ensure         => 'present',
      policy_setting => 'MACHINE\System\CurrentControlSet\Control\Lsa\CrashOnAuditFail',
      policy_type    => 'Registry Values',
      policy_value   => '4,0',
    }
  }

  if($harden_windows_server::ensure_devices_allowed_to_format_and_eject_removable_media_is_set_to_administrators) {
    local_security_policy { 'Devices: Allowed to format and eject removable media':
      ensure         => 'present',
      policy_setting => 'MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\AllocateDASD',
      policy_type    => 'Registry Values',
      policy_value   => '1,"0"',
    }
  }

  if($harden_windows_server::ensure_devices_prevent_users_from_installing_printer_drivers_is_set_to_enabled) {
    local_security_policy { 'Devices: Prevent users from installing printer drivers':
      ensure         => 'present',
      policy_setting => 'MACHINE\System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers\AddPrinterDrivers',
      policy_type    => 'Registry Values',
      policy_value   => '4,1',
    }
  }


  if($harden_windows_server::ensure_domain_controller_allow_server_operators_to_schedule_tasks_is_set_to_disabled) {
    if($harden_windows_server::is_domain_controller) {
      registry::value { 'SubmitControl':
        key   => 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa',
        value => 'SubmitControl',
        type  => 'dword',
        data  => '0x00000000',
      }
    }
  }

  if($harden_windows_server::ensure_domain_controller_ldap_server_signing_requirements_is_set_to_require_signing) {
    if($harden_windows_server::is_domain_controller) {
      registry::value { 'LDAPServerIntegrity':
        key   => 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Service\NTDS\Parameters',
        value => 'LDAPServerIntegrity',
        type  => 'dword',
        data  => '0x00000002',
      }
    }
  }

  if($harden_windows_server::ensure_domain_controller_refuse_machine_account_password_changes_is_set_to_disabled) {
    if($harden_windows_server::is_domain_controller) {
      registry::value { 'RefusePasswordChange':
        key   => 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Service\Netlogon\Parameters',
        value => 'RefusePasswordChange',
        type  => 'dword',
        data  => '0x00000000',
      }
    }
  }

  if($harden_windows_server::ensure_domain_member_digitally_encrypt_or_sign_secure_channel_data_always_is_set_to_enabled) {
    local_security_policy { 'Domain member: Digitally encrypt or sign secure channel data (always)':
      ensure         => 'present',
      policy_setting => 'MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\RequireSignOrSeal',
      policy_type    => 'Registry Values',
      policy_value   => '4,1',
    }
  }

  if($harden_windows_server::ensure_domain_member_digitally_encrypt_or_sign_secure_channel_data_when_possible_is_set_to_enabled) {
    local_security_policy { 'Domain member: Digitally encrypt secure channel data (when possible)':
      ensure         => 'present',
      policy_setting => 'MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\SealSecureChannel',
      policy_type    => 'Registry Values',
      policy_value   => '4,1',
    }
  }

  if($harden_windows_server::ensure_domain_member_digitally_sign_secure_channel_data_when_possible_is_set_to_enabled) {
    local_security_policy { 'Domain member: Digitally sign secure channel data (when possible)':
      ensure         => 'present',
      policy_setting => 'MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\SignSecureChannel',
      policy_type    => 'Registry Values',
      policy_value   => '4,1',
    }
  }

  if($harden_windows_server::ensure_domain_member_disable_machine_account_password_changes_is_set_to_disabled) {
    local_security_policy { 'Domain member: Disable machine account password changes':
      ensure         => 'present',
      policy_setting => 'MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\DisablePasswordChange',
      policy_type    => 'Registry Values',
      policy_value   => '4,0',
    }
  }

  if($harden_windows_server::ensure_domain_member_maximum_machine_account_password_age_is_set_to_30_or_fewer_days_but_not_0) {
    local_security_policy { 'Domain member: Maximum machine account password age':
      ensure         => 'present',
      policy_setting => 'MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\MaximumPasswordAge',
      policy_type    => 'Registry Values',
      policy_value   => '4,30',
    }
  }

  if($harden_windows_server::ensure_domain_member_require_strong_session_key_windows_2000_or_later_is_set_to_enabled) {
    local_security_policy { 'Domain member: Require strong (Windows 2000 or later) session key':
      ensure         => 'present',
      policy_setting => 'MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\RequireStrongKey',
      policy_type    => 'Registry Values',
      policy_value   => '4,1',
    }
  }

  if($harden_windows_server::ensure_interactive_logon_do_not_display_last_user_name_is_set_to_enabled) {
    local_security_policy { 'Interactive logon: Do not display last user name':
      ensure         => 'present',
      policy_setting => 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\DontDisplayLastUserName',
      policy_type    => 'Registry Values',
      policy_value   => '4,1',
    }
  }

  if($harden_windows_server::ensure_interactive_logon_do_not_require_ctrl_alt_del_is_set_to_disabled) {
    local_security_policy { 'Interactive logon: Do not require CTRL+ALT+DEL':
      ensure         => 'present',
      policy_setting => 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\DisableCAD',
      policy_type    => 'Registry Values',
      policy_value   => '4,0',
    }
  }

  # These texts should be organization specific, will not manage in first release
  # #Choose a better text
  # if($harden_windows_server::configure_interactive_logon_message_text_for_users_attempting_to_log_on) {
  #   local_security_policy { 'Interactive logon: Message text for users attempting to log on':
  #     ensure         => 'present',
  #     policy_setting => 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\LegalNoticeText',
  #     policy_type    => 'Registry Values',
  #     policy_value   => '7,Welcome!',
  #   }
  # }
  #
  # #Choose a better text
  # if($harden_windows_server::configure_interactive_logon_message_title_for_users_attempting_to_log_on) {
  #   local_security_policy { 'Interactive logon: Message title for users attempting to log on':
  #     ensure         => 'present',
  #     policy_setting => 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\LegalNoticeCaption',
  #     policy_type    => 'Registry Values',
  #     policy_value   => '1,"Title Bar"',
  #   }
  # }

  if($harden_windows_server::ensure_interactive_logon_number_of_previous_logons_to_cache_is_set_to_4_or_fewer_logons) {
    if(!$harden_windows_server::is_domain_controller) {
      local_security_policy { 'Interactive logon: Number of previous logons to cache (in case domain controller is not available)':
        ensure         => 'present',
        policy_setting => 'MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\CachedLogonsCount',
        policy_type    => 'Registry Values',
        policy_value   => '1,"4"',
      }
    }
  }

  if($harden_windows_server::ensure_interactive_logon_prompt_user_to_change_password_before_expiration_is_set_to_between_5_and_14_days) {
    local_security_policy { 'Interactive logon: Prompt user to change password before expiration':
      ensure         => 'present',
      policy_setting => 'MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\PasswordExpiryWarning',
      policy_type    => 'Registry Values',
      policy_value   => '4,5',
    }
  }

  if($harden_windows_server::ensure_interactive_logon_require_domain_controller_authentication_to_unlock_workstation_is_set_to_enabled) {
    if(!$harden_windows_server::is_domain_controller) {
      local_security_policy { 'Interactive logon: Require Domain Controller authentication to unlock workstation':
        ensure         => 'present',
        policy_setting => 'MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\ForceUnlockLogon',
        policy_type    => 'Registry Values',
        policy_value   => '4,1',
      }
    }
  }

  if($harden_windows_server::ensure_interactive_logon_smart_card_removal_behavior_is_set_to_lock_workstation_or_higher) {
    local_security_policy { 'Interactive logon: Smart card removal behavior':
      ensure         => 'present',
      policy_setting => 'MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\ScRemoveOption',
      policy_type    => 'Registry Values',
      policy_value   => '1,"1"',
    }
  }

  if($harden_windows_server::ensure_microsoft_network_client_digitally_sign_communications_always_is_set_to_enabled) {
    local_security_policy { 'Microsoft network client: Digitally sign communications (always)':
      ensure         => 'present',
      policy_setting => 'MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\RequireSecuritySignature',
      policy_type    => 'Registry Values',
      policy_value   => '4,1',
    }
  }

  if($harden_windows_server::ensure_microsoft_network_client_digitally_sign_communications_if_server_agrees_is_set_to_enabled) {
    local_security_policy { 'Microsoft network client: Digitally sign communications (if server agrees)':
      ensure         => 'present',
      policy_setting => 'MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\EnableSecuritySignature',
      policy_type    => 'Registry Values',
      policy_value   => '4,1',
    }
  }

  if($harden_windows_server::ensure_microsoft_network_client_send_unencrypted_password_to_third_party_smb_servers_is_set_to_disabled) {
    local_security_policy { 'Microsoft network client: Send unencrypted password to third-party SMB servers':
      ensure         => 'present',
      policy_setting => 'MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\EnablePlainTextPassword',
      policy_type    => 'Registry Values',
      policy_value   => '4,0',
    }
  }

  if($harden_windows_server::ensure_microsoft_network_server_idle_time_required_before_suspending_session_is_set_to_15_or_fewer_minutes) {
    local_security_policy { 'Microsoft network server: Amount of idle time required before suspending session':
      ensure         => 'present',
      policy_setting => 'MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\AutoDisconnect',
      policy_type    => 'Registry Values',
      policy_value   => '4,15',
    }
  }

  if($harden_windows_server::ensure_microsoft_network_server_digitally_sign_communications_always_is_set_to_enabled) {
    local_security_policy { 'Microsoft network server: Digitally sign communications (always)':
      ensure         => 'present',
      policy_setting => 'MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\RequireSecuritySignature',
      policy_type    => 'Registry Values',
      policy_value   => '4,1',
    }
  }

  if($harden_windows_server::ensure_microsoft_network_server_digitally_sign_communications_if_client_agrees_is_set_to_enabled) {
    local_security_policy { 'Microsoft network server: Digitally sign communications (if client agrees)':
      ensure         => 'present',
      policy_setting => 'MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\EnableSecuritySignature',
      policy_type    => 'Registry Values',
      policy_value   => '4,1',
    }
  }

  if($harden_windows_server::ensure_microsoft_network_server_disconnect_clients_when_logon_hours_expire_is_set_to_enabled) {
    local_security_policy { 'Microsoft network server: Disconnect clients when logon hours expire':
      ensure         => 'present',
      policy_setting => 'MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\EnableForcedLogOff',
      policy_type    => 'Registry Values',
      policy_value   => '4,1',
    }
  }

  if($harden_windows_server::ensure_microsoft_network_server_spn_target_name_validation_level_is_set_to_accept_if_provided_by_client) {
    if(!$harden_windows_server::is_domain_controller) {
      registry::value { 'SmbServerNameHardeningLevel':
        key   => 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters',
        value => 'SmbServerNameHardeningLevel',
        type  => 'dword',
        data  => '0x00000001',
      }
    }
  }

  if($harden_windows_server::ensure_network_access_allow_anonymous_sid_name_tranlation_is_set_to_disabled) {
    local_security_policy { 'Network access: Allow anonymous SID/name translation':
      ensure         => 'present',
      policy_setting => 'LSAAnonymousNameLookup',
      policy_type    => 'System Access',
      policy_value   => '0',
    }
  }

  if($harden_windows_server::ensure_network_access_do_not_allow_anonymous_enumeration_of_sam_accounts_is_set_to_enabled) {
    if(!$harden_windows_server::is_domain_controller) {
      local_security_policy { 'Network access: Do not allow anonymous enumeration of SAM accounts':
        ensure         => 'present',
        policy_setting => 'MACHINE\System\CurrentControlSet\Control\Lsa\RestrictAnonymousSAM',
        policy_type    => 'Registry Values',
        policy_value   => '4,1',
      }
    }
  }

  if($harden_windows_server::ensure_network_access_do_not_allow_anonymous_enumeration_of_sam_accounts_and_shared_is_set_to_enabled) {
    if(!$harden_windows_server::is_domain_controller) {
      local_security_policy { 'Network access: Do not allow anonymous enumeration of SAM accounts and shares':
        ensure         => 'present',
        policy_setting => 'MACHINE\System\CurrentControlSet\Control\Lsa\RestrictAnonymous',
        policy_type    => 'Registry Values',
        policy_value   => '4,1',
      }
    }
  }

  if($harden_windows_server::ensure_network_access_do_not_allow_storage_of_password_and_credentials_for_authentication_is_set_to_enabled) {
    local_security_policy { 'Network access: Do not allow storage of passwords and credentials for network authentication':
      ensure         => 'present',
      policy_setting => 'MACHINE\System\CurrentControlSet\Control\Lsa\DisableDomainCreds',
      policy_type    => 'Registry Values',
      policy_value   => '4,0',
    }
  }

  if($harden_windows_server::ensure_network_access_let_everyone_permissions_apply_to_anonymous_users_is_set_to_disabled) {
    local_security_policy { 'Network access: Let Everyone permissions apply to anonymous users':
      ensure         => 'present',
      policy_setting => 'MACHINE\System\CurrentControlSet\Control\Lsa\EveryoneIncludesAnonymous',
      policy_type    => 'Registry Values',
      policy_value   => '4,0',
    }
  }

  #The data is invalid
  #these both need to include "BROWSER" when the legacy computer browser service is enabled, not sure how to handle
  # if($harden_windows_server::configure_network_access_named_pipes_that_can_be_accessed_anonymously) {
  #   if($harden_windows_server::is_domain_controller) {
  #     local_security_policy { 'Network access: Named Pipes that can be accessed anonymously':
  #       ensure         => 'present',
  #       policy_setting => 'MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\NullSessionPipes',
  #       policy_type    => 'Registry Values',
  #       policy_value   => '7,LSARPC"," NETLOGON"," SAMR',
  #     }
  #   } else {
  #     local_security_policy { 'Network access: Named Pipes that can be accessed anonymously':
  #       ensure         => 'absent',
  #     }
  #   }
  # }

  if($harden_windows_server::configure_network_access_remotely_accessible_registry_paths) {
    local_security_policy { 'Network access: Remotely accessible registry paths':
      ensure         => 'present',
      policy_setting => 'MACHINE\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths\Machine',
      policy_type    => 'Registry Values',
      policy_value   => '7,System\CurrentControlSet\Control\ProductOptions,System\CurrentControlSet\Control\Server Applications,Software\Microsoft\Windows NT\CurrentVersion',
    }
  }

  #this needs to include more paths for certain roles
  if($harden_windows_server::configure_network_access_remotely_accessible_registry_paths_and_sub_paths) {
    local_security_policy { 'Network access: Remotely accessible registry paths and sub-paths':
      ensure         => 'present',
      policy_setting => 'MACHINE\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths\Machine',
      policy_type    => 'Registry Values',
      policy_value   => '7,System\CurrentControlSet\Control\Print\Printers,System\CurrentControlSet\Services\Eventlog,Software\Microsoft\OLAP Server,Software\Microsoft\Windows NT\CurrentVersion\Print,Software\Microsoft\Windows NT\CurrentVersion\Windows,System\CurrentControlSet\Control\ContentIndex,System\CurrentControlSet\Control\Terminal Server,System\CurrentControlSet\Control\Terminal Server\UserConfig,System\CurrentControlSet\Control\Terminal Server\DefaultUserConfiguration,Software\Microsoft\Windows NT\CurrentVersion\Perflib,System\CurrentControlSet\Services\SysmonLog',
    }
  }

  if($harden_windows_server::ensure_network_access_restrict_anonymous_access_to_named_pipes_and_shares_is_set_to_enabled) {
    local_security_policy { 'Network access: Restrict anonymous access to Named Pipes and Shares':
      ensure         => 'present',
      policy_setting => 'MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\RestrictNullSessAccess',
      policy_type    => 'Registry Values',
      policy_value   => '4,1',
    }t
  }

  #The data is invalid
  # if($harden_windows_server::ensure_network_access_shares_that_can_be_accessed_anonymously_is_set_to_none) {
  #   local_security_policy { 'Network access: Shares that can be accessed anonymously':
  #     ensure         => 'absent',
  #   }
  # }

  if($harden_windows_server::ensure_network_access_sharing_and_security_model_for_local_accounts_is_set_to_classic) {
    local_security_policy { 'Network access: Sharing and security model for local accounts':
      ensure         => 'present',
      policy_setting => 'MACHINE\System\CurrentControlSet\Control\Lsa\ForceGuest',
      policy_type    => 'Registry Values',
      policy_value   => '4,0',
    }
  }

  if($harden_windows_server::ensure_network_security_allow_local_system_to_use_computer_identity_for_ntlm_is_set_to_enabled) {
    local_security_policy { 'Network security: All Local System to use computer identity for NTLM':
      ensure         => 'present',
      policy_setting => 'MACHINE\System\CurrentControlSet\Control\Lsa\UseMachineId',
      policy_type    => 'Registry Values',
      policy_value   => '4,1',
    }
  }

  if($harden_windows_server::ensure_network_security_allow_localsystem_null_session_fallback_is_set_to_disabled) {
    registry::value { 'allownullsessionfallback':
      key   => 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0',
      value => 'allownullsessionfallback',
      type  => 'dword',
      data  => '0x00000000',
    }
  }

  if($harden_windows_server::ensure_network_security_allow_pku2u_authentication_requests_to_use_online_identities_is_set_to_disabled) {
    registry::value { 'AllowOnlineID':
      key   => 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\pku2u',
      value => 'AllowOnlineID',
      type  => 'dword',
      data  => '0x00000000',
    }
  }

  if($harden_windows_server::ensure_network_security_configure_encryption_types_allow_for_kerberos) {
    registry::value { 'SupportedEncryptionTypes':
      key   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters',
      value => 'SupportedEncryptionTypes',
      type  => 'dword',
      data  => '0x7ffffffc',
    }
  }

  if($harden_windows_server::ensure_network_security_do_not_store_lan_manager_hash_value_on_next_password_change_is_set_to_enabled) {
    registry::value { 'NoLmHash':
      key   => 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa',
      value => 'NoLmHash',
      type  => 'dword',
      data  => '0x00000001',
    }
  }

  if($harden_windows_server::ensure_network_security_force_logoff_when_logon_hours_expire_is_set_to_enabled) {
    local_security_policy { 'Network security: Force logoff when logon hours expire':
      ensure         => 'present',
      policy_setting => 'ForceLogoffWhenHourExpire',
      policy_type    => 'System Access',
      policy_value   => '1',
    }
  }

  if($harden_windows_server::ensure_network_security_lan_manager_authentication_level_is_set_to_send_ntlmv2_response_only) {
    local_security_policy { 'Network security: LAN Manager authentication level':
      ensure         => 'present',
      policy_setting => 'MACHINE\System\CurrentControlSet\Control\Lsa\LmCompatibilityLevel',
      policy_type    => 'Registry Values',
      policy_value   => '4,5',
    }
  }

  if($harden_windows_server::ensure_network_security_ldap_client_signing_requirements_is_set_to_negotiate_signing) {
    local_security_policy { 'Network security: LDAP client signing requirements':
      ensure         => 'present',
      policy_setting => 'MACHINE\System\CurrentControlSet\Services\LDAP\LDAPClientIntegrity',
      policy_type    => 'Registry Values',
      policy_value   => '4,1',
    }
  }

  if($harden_windows_server::ensure_network_security_minimum_session_security_for_ntlm_ssp_based_clients) {
    local_security_policy { 'Network security: Minimum session security for NTLM SSP based (including secure RPC) clients':
      ensure         => 'present',
      policy_setting => 'MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\NTLMMinClientSec',
      policy_type    => 'Registry Values',
      policy_value   => '4,537395200',
    }
  }

  if($harden_windows_server::ensure_network_security_minimum_session_security_for_ntlm_ssp_based_servers) {
    local_security_policy { 'Network security: Minimum session security for NTLM SSP based (including secure RPC) servers':
      ensure         => 'present',
      policy_setting => 'MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\NTLMMinServerSec',
      policy_type    => 'Registry Values',
      policy_value   => '4,537395200',
    }
  }

  if($harden_windows_server::ensure_shutdown_allow_system_to_be_shutdown_without_having_to_logon_is_set_to_disabled) {
    local_security_policy { 'Shutdown: Allow system to be shut down without having to log on':
      ensure         => 'present',
      policy_setting => 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ShutdownWithoutLogon',
      policy_type    => 'Registry Values',
      policy_value   => '4,0',
    }
  }

  if($harden_windows_server::ensure_system_objects_require_case_insensitivity_for_non_windows_subsystems_is_enabled) {
    local_security_policy { 'System objects: Require case insensitivity for non-Windows subsystems':
      ensure         => 'present',
      policy_setting => 'MACHINE\System\CurrentControlSet\Control\Session Manager\Kernel\ObCaseInsensitive',
      policy_type    => 'Registry Values',
      policy_value   => '4,1',
    }
  }

  if($harden_windows_server::ensure_system_objects_strengthen_default_permissions_of_internal_system_objects_is_enabled) {
    local_security_policy { 'System objects: Strengthen default permissions of internal system objects (e.g., Symbolic Links)':
      ensure         => 'present',
      policy_setting => 'MACHINE\System\CurrentControlSet\Control\Session Manager\ProtectionMode',
      policy_type    => 'Registry Values',
      policy_value   => '4,1',
    }
  }

  if($harden_windows_server::ensure_system_settings_optional_subsystems_is_set_to_defined_blank) {
    local_security_policy { 'System settings: Optional subsystems':
      ensure         => 'present',
      policy_setting => 'MACHINE\System\CurrentControlSet\Control\Session Manager\SubSystems\optional',
      policy_type    => 'Registry Values',
      policy_value   => '7,Defined: (blank)',
    }
  }

  if($harden_windows_server::ensure_user_account_control_admin_approval_mode_for_the_admin_account_is_enabled) {
    local_security_policy { 'User Account Control: Admin Approval Mode for the Built-in Administrator account':
      ensure         => 'present',
      policy_setting => 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken',
      policy_type    => 'Registry Values',
      policy_value   => '4,1',
    }
  }

  if($harden_windows_server::ensure_user_account_control_allow_uiaccess_applications_to_prompt_for_elevation_is_disabled) {
    local_security_policy { 'User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop':
      ensure         => 'present',
      policy_setting => 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle',
      policy_type    => 'Registry Values',
      policy_value   => '4,0',
    }
  }

  if($harden_windows_server::ensure_user_account_control_behavior_of_the_elevation_prompt_for_administrators_in_admin_approval_mode) {
    local_security_policy { 'User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode':
      ensure         => 'present',
      policy_setting => 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin',
      policy_type    => 'Registry Values',
      policy_value   => '4,2',
    }
  }

  if($harden_windows_server::ensure_user_account_control_behavior_of_the_elevation_prompt_for_standard_users) {
    local_security_policy { 'User Account Control: Behavior of the elevation prompt for standard users':
      ensure         => 'present',
      policy_setting => 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser',
      policy_type    => 'Registry Values',
      policy_value   => '4,0',
    }
  }

  if($harden_windows_server::ensure_user_account_control_detect_application_installations_and_prompt_for_elevation_is_enabled) {
    local_security_policy { 'User Account Control: Detect application installations and prompt for elevation':
      ensure         => 'present',
      policy_setting => 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection',
      policy_type    => 'Registry Values',
      policy_value   => '4,1',
    }
  }

  if($harden_windows_server::ensure_user_account_control_only_elevate_uiaccess_applications_that_are_installed_in_secure_locations) {
    local_security_policy { 'User Account Control: Only elevate UIAccess applications that are installed in secure locations':
      ensure         => 'present',
      policy_setting => 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths',
      policy_type    => 'Registry Values',
      policy_value   => '4,1',
    }
  }

  if($harden_windows_server::ensure_user_account_control_run_all_administrators_in_admin_approval_mode_is_enabled) {
    local_security_policy { 'User Account Control: Run all administrators in Admin Approval Mode':
      ensure         => 'present',
      policy_setting => 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA',
      policy_type    => 'Registry Values',
      policy_value   => '4,1',
    }
  }

  if($harden_windows_server::ensure_user_account_control_switch_to_the_secure_desktop_when_prompting_for_elevation_is_enabled) {
    local_security_policy { 'User Account Control: Switch to the secure desktop when prompting for elevation':
      ensure         => 'present',
      policy_setting => 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop',
      policy_type    => 'Registry Values',
      policy_value   => '4,1',
    }
  }

  if($harden_windows_server::ensure_user_account_control_virtualize_file_and_registry_write_failures_to_per_user_location_is_enabled) {
    local_security_policy { 'User Account Control: Virtualize file and registry write failures to per-user locations':
      ensure         => 'present',
      policy_setting => 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization',
      policy_type    => 'Registry Values',
      policy_value   => '4,1',
    }
  }

  if($harden_windows_server::ensure_windows_firewall_domain_firewall_state_is_set_to_on_recommended) {
    registry::value { 'DomainEnableFirewall':
      key   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile',
      value => 'EnableFirewall',
      type  => 'dword',
      data  => '0x00000001',
    }
  }

  if($harden_windows_server::ensure_windows_firewall_domain_inbound_connections_is_set_to_block_default) {
    registry::value { 'DomainDefaultInboundAction':
      key   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile',
      value => 'DefaultInboundAction',
      type  => 'dword',
      data  => '0x00000001',
    }
  }

  if($harden_windows_server::ensure_windows_firewall_domain_outbound_connections_is_set_to_allow_default) {
    registry::value { 'DomainDefaultOutboundAction':
      key   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile',
      value => 'DefaultOutboundAction',
      type  => 'dword',
      data  => '0x00000000',
    }
  }

  if($harden_windows_server::ensure_windows_firewall_domain_settings_display_a_notification_is_set_to_no) {
    registry::value { 'DomainbDisableNotifications':
      key   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile',
      value => 'DisableNotifications',
      type  => 'dword',
      data  => '0x00000001',
    }
  }

  if($harden_windows_server::ensure_windows_firewall_domain_settings_apply_local_firewall_rules_is_set_to_yes_default) {
    registry::value { 'DomainAllowLocalPolicyMerge':
      key   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile',
      value => 'AllowLocalPolicyMerge',
      type  => 'dword',
      data  => '0x00000001',
    }
  }

  if($harden_windows_server::ensure_windows_firewall_domain_settings_apply_local_connection_security_rules_is_yes) {
    registry::value { 'DomainAllowLocalIPsecPolicyMerge':
      key   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile',
      value => 'AllowLocalIPsecPolicyMerge',
      type  => 'dword',
      data  => '0x00000001',
    }
  }

  if($harden_windows_server::ensure_windows_firewall_domain_logging_name_is_set_to_domainfwlog) {
    registry::value { 'DomainLogFilePath':
      key   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging',
      value => 'LogFilePath',
      type  => 'string',
      data  => '%systemroot%\system32\logfiles\firewall\domainfw.log',
    }
  }

  if($harden_windows_server::ensure_windows_firewall_domain_logging_size_limit_is_16384_or_greater) {
    registry::value { 'DomainLogFileSize':
      key   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging',
      value => 'LogFileSize',
      type  => 'dword',
      data  => '0x00004000',
    }
  }

  if($harden_windows_server::ensure_windows_firewall_domain_logging_log_dropped_packets_is_set_to_yes) {
    registry::value { 'DomainLogDroppedPackets':
      key   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging',
      value => 'LogDroppedPackets',
      type  => 'dword',
      data  => '0x00000001',
    }
  }

  if($harden_windows_server::ensure_windows_firewall_domain_logging_log_successful_connections_is_set_to_yes) {
    registry::value { 'DomainLogSuccessfulConnections':
      key   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging',
      value => 'LogSuccessfulConnections',
      type  => 'dword',
      data  => '0x00000001',
    }
  }

  if($harden_windows_server::ensure_windows_firewall_private_firewall_state_is_set_to_on_recommended) {
    registry::value { 'PrivateEnableFirewall':
      key   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile',
      value => 'EnableFirewall',
      type  => 'dword',
      data  => '0x00000001',
    }
  }

  if($harden_windows_server::ensure_windows_firewall_private_inbound_connections_is_set_to_block_default) {
    registry::value { 'PrivateDefaultInboundAction':
      key   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile',
      value => 'DefaultInboundAction',
      type  => 'dword',
      data  => '0x00000001',
    }
  }

  if($harden_windows_server::ensure_windows_firewall_private_outbound_connections_is_set_to_allow_default) {
    registry::value { 'PrivateDefaultOutboundAction':
      key   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile',
      value => 'DefaultOutboundAction',
      type  => 'dword',
      data  => '0x00000000',
    }
  }

  if($harden_windows_server::ensure_windows_firewall_private_settings_display_a_notification_is_set_to_no) {
    registry::value { 'PrivateDisableNotifications':
      key   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile',
      value => 'DisableNotifications',
      type  => 'dword',
      data  => '0x00000001',
    }
  }

  if($harden_windows_server::ensure_windows_firewall_private_settings_apply_local_firewall_rules_is_set_to_yes_default) {
    registry::value { 'PrivateAllowLocalPolicyMerge':
      key   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile',
      value => 'AllowLocalPolicyMerge',
      type  => 'dword',
      data  => '0x00000001',
    }
  }

  if($harden_windows_server::ensure_windows_firewall_private_settings_apply_local_connection_security_rules_is_set_to_yes_default) {
    registry::value { 'PrivateAllowLocalIPsecPolicyMerge':
      key   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile',
      value => 'AllowLocalIPsecPolicyMerge',
      type  => 'dword',
      data  => '0x00000001',
    }
  }

  if($harden_windows_server::ensure_windows_firewall_private_logging_name_is_set_to_privatefwlog) {
    registry::value { 'PrivateLogFilePath':
      key   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging',
      value => 'LogFilePath',
      type  => 'string',
      data  => '%systemroot%\system32\logfiles\firewall\privatefw.log',
    }
  }

  if($harden_windows_server::ensure_windows_firewall_private_logging_size_limit_is_set_to_16384_or_greater) {
    registry::value { 'PrivateLogFileSize':
      key   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging',
      value => 'LogFileSize',
      type  => 'dword',
      data  => '0x00004000',
    }
  }

  if($harden_windows_server::ensure_windows_firewall_private_logging_log_dropped_packets_is_set_to_yes) {
    registry::value { 'PrivateLogDroppedPackets':
      key   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging',
      value => 'LogDroppedPackets',
      type  => 'dword',
      data  => '0x00000001',
    }
  }

  if($harden_windows_server::ensure_windows_firewall_private_logging_log_successful_connections_is_set_to_yes) {
    registry::value { 'PrivateLogSuccessfulConnections':
      key   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging',
      value => 'LogSuccessfulConnections',
      type  => 'dword',
      data  => '0x00000001',
    }
  }

  if($harden_windows_server::ensure_windows_firewall_public_firewall_state_is_set_to_on_recommended) {
    registry::value { 'PublicEnableFirewall':
      key   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile',
      value => 'EnableFirewall',
      type  => 'dword',
      data  => '0x00000001',
    }
  }

  if($harden_windows_server::ensure_windows_firewall_public_inbound_connections_is_set_to_block_default) {
    registry::value { 'PublicDefaultInboundAction':
      key   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile',
      value => 'DefaultInboundAction',
      type  => 'dword',
      data  => '0x00000001',
    }
  }

  if($harden_windows_server::ensure_windows_firewall_public_outbound_connections_is_set_to_allow_default) {
    registry::value { 'PublicDefaultOutboundAction':
      key   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile',
      value => 'DefaultOutboundAction',
      type  => 'dword',
      data  => '0x00000000',
    }
  }

  if($harden_windows_server::ensure_windows_firewall_public_settings_display_a_notification_is_set_to_yes) {
    registry::value { 'PublicDisableNotifications':
      key   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile',
      value => 'DisableNotifications',
      type  => 'dword',
      data  => '0x00000000',
    }
  }

  if($harden_windows_server::ensure_windows_firewall_public_settings_apply_local_firewall_rules_is_set_to_no) {
    registry::value { 'PublicAllowLocalPolicyMerge':
      key   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile',
      value => 'AllowLocalPolicyMerge',
      type  => 'dword',
      data  => '0x00000000',
    }
  }

  if($harden_windows_server::ensure_windows_firewall_public_settings_apply_local_connection_security_rules_is_set_to_no) {
    registry::value { 'PublicAllowLocalIPsecPolicyMerge':
      key   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile',
      value => 'AllowLocalIPsecPolicyMerge',
      type  => 'dword',
      data  => '0x00000000',
    }
  }

  if($harden_windows_server::ensure_windows_firewall_public_logging_name_is_set_to_publicfwlog) {
    registry::value { 'PublicLogFilePath':
      key   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging',
      value => 'LogFilePath',
      type  => 'string',
      data  => '%systemroot%\system32\logfiles\firewall\publicfw.log',
    }
  }

  if($harden_windows_server::ensure_windows_firewall_public_logging_size_limit_is_set_to_16384_or_greater) {
    registry::value { 'PublicLogFileSize':
      key   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging',
      value => 'LogFileSize',
      type  => 'dword',
      data  => '0x00004000',
    }
  }

  if($harden_windows_server::ensure_windows_firewall_public_logging_log_dropped_packets_is_set_to_yes) {
    registry::value { 'PublicLogDroppedPackets':
      key   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging',
      value => 'LogDroppedPackets',
      type  => 'dword',
      data  => '0x00000001',
    }
  }

  if($harden_windows_server::ensure_windows_firewall_public_logging_log_successful_connections_is_set_to_yes) {
    registry::value { 'PublicLogSuccessfulConnections':
      key   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging',
      value => 'LogSuccessfulConnections',
      type  => 'dword',
      data  => '0x00000001',
    }
  }

  if($harden_windows_server::advanced_audit_policy_configuration) {
    auditpol { 'Credential Validation':
      success => 'enable',
      failure => 'enable',
    }
    auditpol { 'Application Group Management':
      success => 'enable',
      failure => 'enable',
    }
    auditpol { 'Computer Account Management':
      success => 'enable',
      failure => 'enable',
    }
    if($harden_windows_server::is_domain_controller) {
      auditpol { 'Distribution Group Management':
        success => 'enable',
        failure => 'enable',
      }
    }
    auditpol { 'Other Account Management Events':
      success => 'enable',
      failure => 'enable',
    }
    auditpol { 'Security Group Management':
      success => 'enable',
      failure => 'enable',
    }
    auditpol { 'User Account Management':
      success => 'enable',
      failure => 'enable',
    }
    auditpol { 'Process Creation':
      success => 'enable',
      failure => 'disable',
    }
    if($harden_windows_server::is_domain_controller) {
      auditpol { 'Directory Service Changes':
        success => 'enable',
        failure => 'enable',
      }
      auditpol { 'Directory Service Access':
        success => 'enable',
        failure => 'enable',
      }
    }
    auditpol { 'Account Lockout':
      success => 'enable',
      failure => 'disable',
    }
    auditpol { 'Logoff':
      success => 'enable',
      failure => 'disable',
    }
    auditpol { 'Logon':
      success => 'enable',
      failure => 'enable',
    }
    auditpol { 'Other Logon/Logoff Events':
      success => 'enable',
      failure => 'enable',
    }
    auditpol { 'Special Logon':
      success => 'enable',
      failure => 'disable',
    }
    auditpol { 'Audit Policy Change':
      success => 'enable',
      failure => 'enable',
    }
    auditpol { 'Authentication Policy Change':
      success => 'enable',
      failure => 'disable',
    }
    auditpol { 'Sensitive Privilege Use':
      success => 'enable',
      failure => 'enable',
    }
    auditpol { 'IPsec Driver':
      success => 'enable',
      failure => 'enable',
    }
    auditpol { 'Other System Events':
      success => 'enable',
      failure => 'enable',
    }
    auditpol { 'Security State Change':
      success => 'enable',
      failure => 'disable',
    }
    auditpol { 'Security System Extension':
      success => 'enable',
      failure => 'enable',
    }
    auditpol { 'System Integrity':
      success => 'enable',
      failure => 'enable',
    }
  }

  # 18.2
  # Need to install LAPS, might not manage these
  # if($harden_windows_server::ensure_laps_admpwd_gpo_extension_cse_is_installed) {
  #   if(!$harden_windows_server::is_domain_controller) {
  #
  #   }
  # }
  #
  # if($harden_windows_server::ensure_do_not_allow_password_expiration_time_longer_than_required_by_policy_is_set_to_enabled) {
  #   if(!$harden_windows_server::is_domain_controller) {
  #
  #   }
  # }
  #
  # if($harden_windows_server::ensure_enable_local_admin_password_management_is_set_to_enabled) {
  #   if(!$harden_windows_server::is_domain_controller) {
  #
  #   }
  # }
  #
  # if($harden_windows_server::ensure_password_settings_password_complexity_is_set_to_enabled_large_letters_small_letters_numbers_special_characters) {
  #   if(!$harden_windows_server::is_domain_controller) {
  #
  #   }
  # }
  #
  # if($harden_windows_server::ensure_password_settings_password_length_is_set_to_enabled_15_or_more) {
  #   if(!$harden_windows_server::is_domain_controller) {
  #
  #   }
  # }
  #
  # if($harden_windows_server::ensure_password_settings_password_age_days_is_set_to_enabled_30_or_fewer) {
  #   if(!$harden_windows_server::is_domain_controller) {
  #
  #   }
  # }

  # Skipping becuase I have to download a template and it is deprecated, will do last
  # if($harden_windows_server::ensure_mss_autoadminlogon_enable_automatic_logon_not_recommended_is_set_to_disabled) {
  #   registry::value { 'AutoAdminLogon':
  #     key   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon',
  #     value => 'AutoAdminLogon',
  #     type  => 'string',
  #     data  => '0',
  #   }
  # }
  #
  # if($harden_windows_server::ensure_mss_disableipsourcerouting_ipv6_ip_source_routing_protection_level_is_set_to_enabled_highest_protection_source_routing_disabled) {
  #   registry::value { 'DisableIPSourceRouting':
  #     key   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon',
  #     value => 'AutoAdminLogon',
  #     type  => 'string',
  #     data  => '0',
  #   }
  # }
  #
  # if($harden_windows_server::ensure_mss_disableipsourcerouting_ip_source_routing_protection_level_is_set_to_enabled_highest_protection_source_routing_disabled) {
  #
  # }
  #
  # if($harden_windows_server::ensure_mss_enableicmpredirect_allow_icmp_redirects_to_override_ospf_generated_routes_is_set_to_disabled) {
  #
  # }
  #
  # if($harden_windows_server::ensure_mss_keepalivetime_how_often_keepalive_packets_are_sent_in_millisecondsis_set_to_enabled_300000_or_5_minutes) {
  #
  # }
  #
  # if($harden_windows_server::ensure_mss_nonamereleaseondemand_allow_the_computer_to_ignore_netbios_name_release_requests_except_from_wins_server_is_enabled) {
  #
  # }
  #
  # if($harden_windows_server::ensure_mss_performrouterdiscovery_allow_irdp_to_detect_and_configure_default_gateway_addresses_is_set_to_disabled) {
  #
  # }
  #
  # if($harden_windows_server::ensure_mss_safediisearchmode_enable_safe_dll_search_mode_is_set_to_enabled) {
  #
  # }
  #
  # if($harden_windows_server::ensure_mss_screensavergraceperiod_the_time_in_seconds_before_the_screen_saver_grace_period_expired_is_set_to_enabled_5_or_fewer) {
  #
  # }
  #
  # if($harden_windows_server::ensure_mss_tcpmaxdataretranmissions_ipv6_how_many_times_unacknowledged_data_is_retransmitted_is_set_to_enabled_3) {
  #
  # }
  #
  # if($harden_windows_server::ensure_mss_tcpmaxdataretransmissions_how_many_times_unacknowledged_data_is_retransmitted_is_set_to_enabled_3) {
  #
  # }
  #
  # if($harden_windows_server::ensure_mss_warninglevel_percentage_threshold_for_the_security_event_log_is_set_to_enabled_90_or_less) {
  #
  # }

  if($harden_windows_server::ensure_turn_on_mapper_io_lltdio_driver_is_set_to_disabled) {
    registry::value { 'AllowLLTDIOOnDomain':
      key   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LLTD',
      value => 'AllowLLTDIOOnDomain',
      type  => 'dword',
      data  => '0x00000000',
    }
    registry::value { 'AllowLLTDIOOnPublicNet':
      key   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LLTD',
      value => 'AllowLLTDIOOnPublicNet',
      type  => 'dword',
      data  => '0x00000000',
    }
    registry::value { 'EnableLLTDIO':
      key   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LLTD',
      value => 'EnableLLTDIO',
      type  => 'dword',
      data  => '0x00000000',
    }
    registry::value { 'ProhibitLLTDIOOnPrivateNet':
      key   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LLTD',
      value => 'ProhibitLLTDIOOnPrivateNet',
      type  => 'dword',
      data  => '0x00000000',
    }
  }

  if($harden_windows_server::ensure_turn_on_responder_rspndr_driver_is_set_to_disabled) {
    registry::value { 'AllowRspndrOnDomain':
      key   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LLTD',
      value => 'AllowRspndrOnDomain',
      type  => 'dword',
      data  => '0x00000000',
    }
    registry::value { 'AllowRspndrOnPublicNet':
      key   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LLTD',
      value => 'AllowRspndrOnPublicNet',
      type  => 'dword',
      data  => '0x00000000',
    }
    registry::value { 'EnableRspndr':
      key   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LLTD',
      value => 'EnableRspndr',
      type  => 'dword',
      data  => '0x00000000',
    }
    registry::value { 'ProhibitRspndrOnPrivateNet':
      key   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LLTD',
      value => 'ProhibitRspndrOnPrivateNet',
      type  => 'dword',
      data  => '0x00000000',
    }
  }

  if($harden_windows_server::ensure_turn_off_microsoft_peer_to_peer_networking_services_is_set_to_enabled) {
    registry::value { 'PeernetDisabled':
      key   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Peernet',
      value => 'Disabled',
      type  => 'dword',
      data  => '0x00000001',
    }
  }

  if($harden_windows_server::ensure_prohibit_installation_and_configuration_of_network_bridge_on_your_dns_domain_network_is_set_to_enabled) {
    registry::value { 'NC_AllowNetBridge_NLA':
      key   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Network Connections',
      value => 'NC_AllowNetBridge_NLA',
      type  => 'dword',
      data  => '0x00000000',
    }
  }

  if($harden_windows_server::ensure_require_domain_users_to_elevate_when_setting_a_networks_location_is_set_to_enabled) {
    registry::value { 'NC_StdDomainUserSetLocation':
      key   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Network Connections',
      value => 'NC_StdDomainUserSetLocation',
      type  => 'dword',
      data  => '0x00000001',
    }
  }

  # Must install a template first
  # if($harden_windows_server::ensure_hardened_unc_paths_is_set_to_enabled_with_require_mutual_authentication_and_require_integrity_for_all_netlogon_and_sysvol_shares) {
  #
  # }

  # Have to download a thing to add the key
  # if($harden_windows_server::disable_ipv6_ensure_tcpip6_parameter_disabledcomponents_is_set_to_0xff255) {
  #   registry::value { 'DisabledComponents':
  #     key   => 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\TCPIP6\Parameters',
  #     value => 'DisabledComponents',
  #     type  => 'dword',
  #     data  => '0x00000001',
  #   }
  # }

  if($harden_windows_server::ensure_configuration_of_wireless_settings_using_windows_connect_now_is_set_to_disabled) {
    registry::value { 'EnableRegistrars':
      key   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars',
      value => 'EnableRegistrars',
      type  => 'dword',
      data  => '0x00000000',
    }
    registry::value { 'DisableWPDRegistrar':
      key   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars',
      value => 'DisableWPDRegistrar',
      type  => 'dword',
      data  => '0x00000000',
    }
    registry::value { 'DisableUPnPRegistrar':
      key   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars',
      value => 'DisableUPnPRegistrar',
      type  => 'dword',
      data  => '0x00000000',
    }
    registry::value { 'DisableInBand802DOT11Registrar':
      key   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars',
      value => 'DisableInBand802DOT11Registrar',
      type  => 'dword',
      data  => '0x00000000',
    }
    registry::value { 'DisableFlashConfigRegistrar':
      key   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars',
      value => 'DisableFlashConfigRegistrar',
      type  => 'dword',
      data  => '0x00000000',
    }
  }

  if($harden_windows_server::ensure_prohibit_access_of_the_windows_connect_now_wizards_is_set_to_enabled) {
    registry::value { 'DisableWcnUi':
      key   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WCN\UI',
      value => 'DisableWcnUi',
      type  => 'dword',
      data  => '0x00000001',
    }
  }

  # Must download more group policy templates
  # if($harden_windows_server::ensure_apply_uac_restrictions_to_local_accounts_on_network_logons_is_set_to_enabled) {
  #   if(!$harden_windows_server::is_domain_controller) {
  #
  #   }
  # }
  #
  # if($harden_windows_server::ensure_wdigest_authentication_is_set_to_disabled) {
  #
  # }

  # can't find group policy object
  # if($harden_windows_server::ensure_include_command_line_in_process_creation_events_is_set_to_disabled) {
  #
  # }

  if($harden_windows_server::ensure_allow_remote_access_to_the_plug_and_play_interface_is_set_to_disabled) {
    registry::value { 'AllowRemoteRPC':
      key   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Settings',
      value => 'AllowRemoteRPC',
      type  => 'dword',
      data  => '0x00000000',
    }
  }


  if($harden_windows_server::ensure_configure_registry_policy_processing_do_not_apply_during_periodic_background_processing_is_set_to_enabled_false) {
    registry::value { 'NoBackgroundPolicy':
      key   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}',
      value => 'NoBackgroundPolicy',
      type  => 'dword',
      data  => '0x00000000',
    }
  }


  if($harden_windows_server::ensure_configure_registry_policy_processing_process_even_if_the_group_policy_objects_have_not_changed_is_set_to_enabled_true) {
    registry::value { 'NoGPOListChange':
      key   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}',
      value => 'NoGPOListChange',
      type  => 'dword',
      data  => '0x00000000',
    }
  }


  # Can we do ensure => absent on a registry key?
  # if($harden_windows_server::ensure_turn_off_background_refresh_of_group_policy_is_set_to_disabled) {
  #
  # }

  # All Are LEVEL 2
  # if($harden_windows_server::ensure_turn_off_downloading_of_print_drivers_over_http_is_set_to_enabled) {
  #
  # }
  #
  # if($harden_windows_server::ensure_turn_off_handwriting_personalization_data_sharing_is_set_to_enabled) {
  #
  # }
  #
  # if($harden_windows_server::ensure_turn_off_handwriting_recognition_error_reporting_is_set_to_enabled) {
  #
  # }
  #
  # if($harden_windows_server::ensure_turn_off_internet_connection_wizard_if_url_connection_is_referring_to_microsoftcom_is_set_to_enabled) {
  #
  # }
  #
  # if($harden_windows_server::ensure_turn_off_internet_download_for_web_publishing_and_online_ordering_wizards_is_set_to_enabled) {
  #
  # }
  #
  # if($harden_windows_server::ensure_turn_off_internet_file_association_service_is_set_to_enabled) {
  #
  # }
  #
  # if($harden_windows_server::ensure_turn_off_printing_over_http_is_set_to_enabled) {
  #
  # }
  #
  # if($harden_windows_server::ensure_turn_off_registration_if_url_connection_is_referring_to_microsoftcom_is_set_to_enabled) {
  #
  # }
  #
  # if($harden_windows_server::ensure_turn_off_search_companion_content_file_updates_is_set_to_enabled) {
  #
  # }
  #
  # if($harden_windows_server::ensure_turn_off_the_order_prints_picture_task_is_set_to_enabled) {
  #
  # }
  #
  # if($harden_windows_server::ensure_turn_off_the_publish_to_web_task_for_files_and_folders_is_set_to_enabled) {
  #
  # }
  #
  # if($harden_windows_server::ensure_turn_off_the_windows_messenger_customer_experience_improvement_program_is_set_to_enabled) {
  #
  # }
  #
  # if($harden_windows_server::ensure_turn_off_windows_customer_experience_improvement_program_is_set_to_enabled) {
  #
  # }
  #
  # if($harden_windows_server::ensure_turn_off_windows_error_reporting_is_set_to_enabled) {
  #
  # }

  if($harden_windows_server::ensure_always_use_classic_logon) {
    if(!$harden_windows_server::is_domain_controller) {
      registry::value { 'LogonType':
        key   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System',
        value => 'LogonType',
        type  => 'dword',
        data  => '0x00000000',
      }
    }
  }

  # Both Level 2
  # if($harden_windows_server::ensure_require_a_password_when_a_computer_wakes_on_battery_is_set_to_enabled) {
  #
  # }
  #
  # if($harden_windows_server::ensure_require_a_password_when_a_computer_wakes_plugged_in_is_set_to_enabled) {
  #
  # }

  if($harden_windows_server::ensure_configure_offer_remote_assistance_is_set_to_disabled) {
    registry::value { 'fAllowUnsolicited':
      key   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services',
      value => 'fAllowUnsolicited',
      type  => 'dword',
      data  => '0x00000000',
    }
  }

  if($harden_windows_server::ensure_configure_solicited_remote_assistance_is_set_to_disabled) {
    registry::value { 'fAllowToGetHelp':
      key   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services',
      value => 'fAllowToGetHelp',
      type  => 'dword',
      data  => '0x00000000',
    }
  }

  if($harden_windows_server::ensure_enable_rpc_endpoint_mapper_client_authentication_is_set_to_enabled) {
    if(!$harden_windows_server::is_domain_controller) {
      registry::value { 'EnableAuthEpResolution':
        key   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Rpc',
        value => 'EnableAuthEpResolution',
        type  => 'dword',
        data  => '0x00000001',
      }
    }
  }

  # ALL LEVEL 2
  # if($harden_windows_server::ensure_restrict_unauthenticated_rpc_clients_is_set_to_enabled_authenticatied) {
  #   if(!$harden_windows_server::is_domain_controller) {
  #
  #   }
  # }
  #
  # if($harden_windows_server::ensure_microsoft_support_diagnostic_tool_turn_on_msdt_interactive_communication_with_support_provider_is_set_to_disabled) {
  #
  # }
  #
  # if($harden_windows_server::ensure_enable_disable_perftrack_is_set_to_disabled) {
  #
  # }
  #
  # if($harden_windows_server::ensure_enable_windows_ntp_client_is_set_to_enabled) {
  #
  # }
  #
  # if($harden_windows_server::ensure_enable_windows_ntp_server_is_set_to_disabled) {
  #   if(!$harden_windows_server::is_domain_controller) {
  #
  #   }
  # }

  if($harden_windows_server::ensure_disallow_autoplay_for_non_volume_devices_is_set_to_enabled) {
    registry::value { 'NoAutoplayfornonVolume':
      key   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer',
      value => 'NoAutoplayfornonVolume',
      type  => 'dword',
      data  => '0x00000001',
    }
  }

  if($harden_windows_server::ensure_set_the_default_behavior_for_autorun_is_set_to_enabled_do_not_execute_any_autorun_commands) {
    registry::value { 'NoAutorun':
      key   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer',
      value => 'NoAutorun',
      type  => 'dword',
      data  => '0x00000001',
    }
  }

  if($harden_windows_server::ensure_turn_off_autoplay_is_set_to_enabled_all_drives) {
    registry::value { 'NoDriveTypeAutoRun':
      key   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer',
      value => 'NoDriveTypeAutoRun',
      type  => 'dword',
      data  => '0x000000ff',
    }
  }

  # Can't find GPO for this
  # if($harden_windows_server::ensure_do_not_display_the_password_reveal_button_is_set_to_enabled) {
  #
  # }

  if($harden_windows_server::ensure_enumerate_administrator_accounts_on_elevation_is_set_to_disabled) {
    registry::value { 'EnumerateAdministrators':
      key   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI',
      value => 'EnumerateAdministrators',
      type  => 'dword',
      data  => '0x00000000',
    }
  }

  if($harden_windows_server::ensure_turn_off_desktop_gadgets_is_set_to_enabled) {
    registry::value { 'TurnOffSidebar':
      key   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Windows\Sidebar',
      value => 'TurnOffSidebar',
      type  => 'dword',
      data  => '0x00000001',
    }
  }

  if($harden_windows_server::ensure_turn_off_user_installed_desktop_gadgets_is_set_to_enabled) {
    registry::value { 'TurnOffUserInstalledGadgets':
      key   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Windows\Sidebar',
      value => 'TurnOffUserInstalledGadgets',
      type  => 'dword',
      data  => '0x00000001',
    }
  }

  # Have to download a thing and it's deprecated
  # if($harden_windows_server::ensure_emet_551_or_higher_is_installed) {
  #
  # }
  #
  # if($harden_windows_server::ensure_default_action_and_mitigation_settings_is_set_to_enabled_plus_subsettings) {
  #
  # }
  #
  # if($harden_windows_server::ensure_default_protections_for_internet_explorer_is_set_to_enabled) {
  #
  # }
  #
  # if($harden_windows_server::ensure_default_protections_for_popular_software_is_set_to_enabled) {
  #
  # }
  #
  # if($harden_windows_server::ensure_default_protections_for_recommended_software_is_set_to_enabled) {
  #
  # }
  #
  # if($harden_windows_server::ensure_system_aslr_is_set_to_enabled_application_opt_in) {
  #
  # }
  #
  # if($harden_windows_server::ensure_system_dep_is_set_to_enabled_application_opt_out) {
  #
  # }
  #
  # if($harden_windows_server::ensure_system_sehop_is_set_to_enabled_application_opt_out) {
  #
  # }


  if($harden_windows_server::ensure_application_control_event_log_behavior_when_the_log_file_reaches_its_maximum_size_is_set_to_disabled) {
    registry::value { 'ApplicationRetention':
      key   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application',
      value => 'Retention',
      type  => 'string',
      data  => '0',
    }
  }

  if($harden_windows_server::ensure_application_specify_the_maximum_log_file_size_kb_is_set_to_enabled_32768_or_greater) {
    registry::value { 'ApplicationMaxSize':
      key   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application',
      value => 'MaxSize',
      type  => 'dword',
      data  => '0x00008000',
    }
  }

  if($harden_windows_server::ensure_security_control_event_log_behavior_when_the_log_file_reaches_its_maximum_size_is_set_to_disabled) {
    registry::value { 'SecurityRetention':
      key   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security',
      value => 'Retention',
      type  => 'string',
      data  => '0',
    }
  }

  if($harden_windows_server::ensure_security_specify_the_maximum_log_file_size_kb_is_set_to_enabled_196608_or_greater) {
    registry::value { 'SecurityMaxSize':
      key   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security',
      value => 'MaxSize',
      type  => 'dword',
      data  => '0x00030000',
    }
  }

  if($harden_windows_server::ensure_setup_control_event_log_behavior_when_the_log_reaches_its_maximum_size_is_set_to_disabled) {
    registry::value { 'SetupRetention':
      key   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup',
      value => 'Retention',
      type  => 'string',
      data  => '0',
    }
  }

  if($harden_windows_server::ensure_setup_specify_the_maximum_log_file_size_kb_is_set_to_enabled_32768_or_greater) {
    registry::value { 'SetupMaxSize':
      key   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup',
      value => 'MaxSize',
      type  => 'dword',
      data  => '0x00008000',
    }
  }

  if($harden_windows_server::ensure_system_control_event_log_behavior_when_the_log_file_reaches_its_maximum_size_is_set_to_disabled) {
    registry::value { 'SystemRetention':
      key   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\System',
      value => 'Retention',
      type  => 'string',
      data  => '0',
    }
  }

  if($harden_windows_server::ensure_system_specify_the_maximum_log_file_size_kb_is_set_to_enabled_32768_or_greater) {
    registry::value { 'SystemMaxSize':
      key   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\System',
      value => 'MaxSize',
      type  => 'dword',
      data  => '0x00008000',
    }
  }

  if($harden_windows_server::ensure_turn_off_data_execution_prevention_for_explorer_is_set_to_disabled) {
    registry::value { 'NoDataExecutionPrevention':
      key   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer',
      value => 'NoDataExecutionPrevention',
      type  => 'dword',
      data  => '0x00000000',
    }
  }

  if($harden_windows_server::ensure_turn_off_heap_termination_on_corruption_is_set_to_disabled) {
    registry::value { 'NoHeapTerminationOnCorruption':
      key   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer',
      value => 'NoHeapTerminationOnCorruption',
      type  => 'dword',
      data  => '0x00000000',
    }
  }

  if($harden_windows_server::ensure_turn_off_shell_protocol_proteted_mode_is_set_to_disabled) {
    registry::value { 'PreXPSP2ShellProtocolBehavior':
      key   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer',
      value => 'PreXPSP2ShellProtocolBehavior',
      type  => 'dword',
      data  => '0x00000000',
    }
  }

  if($harden_windows_server::ensure_turn_off_location_is_set_to_enabled) {
    registry::value { 'DisableLocation':
      key   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors',
      value => 'DisableLocation',
      type  => 'dword',
      data  => '0x00000001',
    }
  }

  # Can't find these administrative templates
  # if($harden_windows_server::ensure_prevent_the_usage_of_onedrive_for_filestorage_is_set_to_enabled) {
  #
  # }
  #
  # if($harden_windows_server::ensure_prevent_the_usage_of_onedrive_for_file_storage_on_windows_81_is_set_to_enabled) {
  #
  # }

  if($harden_windows_server::ensure_do_not_allow_passwords_to_be_saved_is_set_to_enabled) {
    registry::value { 'DisablePasswordSaving':
      key   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services',
      value => 'DisablePasswordSaving',
      type  => 'dword',
      data  => '0x00000001',
    }
  }

  if($harden_windows_server::ensure_restrict_remote_desktop_services_users_to_a_single_remote_desktop_services_session_is_set_to_enabled) {
    registry::value { 'fSingleSessionPerUser':
      key   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services',
      value => 'fSingleSessionPerUser',
      type  => 'dword',
      data  => '0x00000001',
    }
  }

  if($harden_windows_server::ensure_do_not_allow_com_port_redirection_is_set_to_enabled) {
    registry::value { 'fDisableCcm':
      key   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services',
      value => 'fDisableCcm',
      type  => 'dword',
      data  => '0x00000001',
    }
  }

  if($harden_windows_server::ensure_do_not_allow_drive_redirection_is_set_to_enabled) {
    registry::value { 'fDisableCdm':
      key   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services',
      value => 'fDisableCdm',
      type  => 'dword',
      data  => '0x00000001',
    }
  }

  if($harden_windows_server::ensure_do_not_allow_lpt_port_redirection_is_set_to_enabled) {
    registry::value { 'fDisableLPT':
      key   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services',
      value => 'fDisableLPT',
      type  => 'dword',
      data  => '0x00000001',
    }
  }

  if($harden_windows_server::ensure_do_not_allow_supported_plug_and_play_device_redirection_is_set_to_enabled) {
    registry::value { 'fDisablePNPRedir':
      key   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services',
      value => 'fDisablePNPRedir',
      type  => 'dword',
      data  => '0x00000001',
    }
  }

  if($harden_windows_server::ensure_always_prompt_for_password_upon_connection_is_set_to_enabled) {
    registry::value { 'fPromptForPassword':
      key   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services',
      value => 'fPromptForPassword',
      type  => 'dword',
      data  => '0x00000001',
    }
  }

  if($harden_windows_server::ensure_require_secure_rpc_communication_is_set_to_enabled) {
    registry::value { 'fEncryptRPCTraffic':
      key   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services',
      value => 'fEncryptRPCTraffic',
      type  => 'dword',
      data  => '0x00000001',
    }
  }

  if($harden_windows_server::ensure_set_client_connection_encryption_level_is_set_to_enabled_high_level) {
    registry::value { 'MinEncryptionLevel':
      key   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services',
      value => 'MinEncryptionLevel',
      type  => 'dword',
      data  => '0x00000003',
    }
  }

  if($harden_windows_server::ensure_set_time_limit_for_active_but_idle_remote_desktop_services_sessions_is_set_to_enabled_15_minutes_or_less) {
    registry::value { 'MaxIdleTime':
      key   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services',
      value => 'MaxIdleTime',
      type  => 'dword',
      data  => '0x000dbba0',
    }
  }

  if($harden_windows_server::ensure_set_time_limit_for_disconnected_sessions_is_set_to_enabled_1_minute) {
    registry::value { 'MaxDisconnectionTime':
      key   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services',
      value => 'MaxDisconnectionTime',
      type  => 'dword',
      data  => '0x0000ea60',
    }
  }

  if($harden_windows_server::ensure_do_not_delete_temp_folders_upon_exit_is_set_to_disabled) {
    registry::value { 'DeleteTempDirsOnExit':
      key   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services',
      value => 'DeleteTempDirsOnExit',
      type  => 'dword',
      data  => '0x00000001',
    }
  }

  if($harden_windows_server::ensure_do_not_use_temporary_folders_per_session_is_set_to_disabled) {
    registry::value { 'PerSessionTempDir':
      key   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services',
      value => 'PerSessionTempDir',
      type  => 'dword',
      data  => '0x00000001',
    }
  }

  if($harden_windows_server::ensure_prevent_downloading_of_enclosures_is_set_to_enabled) {
    registry::value { 'DisableEnclosureDownload':
      key   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds',
      value => 'DisableEnclosureDownload',
      type  => 'dword',
      data  => '0x00000001',
    }
  }

  #non default template
  # if($harden_windows_server::ensure_allow_indexing_of_encrypted_files_is_set_to_disabled) {
  #
  # }

  #cant find template, maybe spynet?
  # if($harden_windows_server::ensure_join_microsoft_maps_is_set_to_disabled) {
  #
  # }

  if($harden_windows_server::ensure_configure_default_consent_is_set_to_enabled_always_ask_before_sending_data) {
    registry::value { 'DefaultConsent':
      key   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting\Consent',
      value => 'DefaultConsent',
      type  => 'dword',
      data  => '0x00000001',
    }
  }

  if($harden_windows_server::ensure_allow_user_control_over_installs_is_set_to_disabled) {
    registry::value { 'EnableUserControl':
      key   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer',
      value => 'EnableUserControl',
      type  => 'dword',
      data  => '0x00000000',
    }
  }

  if($harden_windows_server::ensure_always_install_with_elevated_privileges_is_set_to_disabled) {
    registry::value { 'AlwaysInstallElevated':
      key   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer',
      value => 'AlwaysInstallElevated',
      type  => 'dword',
      data  => '0x00000000',
    }
  }

  if($harden_windows_server::ensure_prevent_internet_explorer_security_prompt_for_windows_installer_scripts_is_set_to_disabled) {
    registry::value { 'EnableUserControl':
      key   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer',
      value => 'EnableUserControl',
      type  => 'dword',
      data  => '0x00000000',
    }
  }

  # Need updated template
  # if($harden_windows_server::ensure_turn_on_powershell_script_block_logging_is_set_to_disabled) {
  #
  # }
  #
  # if($harden_windows_server::ensure_turn_on_powershell_transcription_is_set_to_disabled) {
  #
  # }

  if($harden_windows_server::ensure_winrm_client_allow_basic_authentication_is_set_to_disabled) {
    registry::value { 'ClientAllowBasic':
      key   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client',
      value => 'AllowBasic',
      type  => 'dword',
      data  => '0x00000000',
    }
  }

  if($harden_windows_server::ensure_winrm_client_allow_unencrypted_traffic_is_set_to_disabled) {
    registry::value { 'ClientAllowUnencryptedTraffic':
      key   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client',
      value => 'AllowUnencryptedTraffic',
      type  => 'dword',
      data  => '0x00000000',
    }
  }

  if($harden_windows_server::ensure_disallow_digest_authentication_is_set_to_enabled) {
    registry::value { 'AllowDigest':
      key   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client',
      value => 'AllowDigest',
      type  => 'dword',
      data  => '0x00000000',
    }
  }

  if($harden_windows_server::ensure_winrm_service_allow_basic_authentication_is_set_to_disabled) {
    registry::value { 'ServiceAllowBasic':
      key   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service',
      value => 'AllowBasic',
      type  => 'dword',
      data  => '0x00000000',
    }
  }

  # Can't find GPO
  # if($harden_windows_server::ensure_allow_remote_server_management_through_winrm_is_set_to_disabled) {
  #
  # }

  if($harden_windows_server::ensure_winrm_service_allow_unencrypted_traffic_is_set_to_disabled) {
    registry::value { 'ServiceAllowUnencryptedTraffic':
      key   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service',
      value => 'AllowUnencryptedTraffic',
      type  => 'dword',
      data  => '0x00000000',
    }
  }

  # Can't find GPO
  # if($harden_windows_server::ensure_disallow_winrm_from_storing_runas_credentials_is_set_to_enabled) {
  #
  # }

  if($harden_windows_server::ensure_allow_remote_shell_access_is_set_to_disabled) {
    registry::value { 'AllowRemoteShellAccess':
      key   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\WinRS',
      value => 'AllowRemoteShellAccess',
      type  => 'dword',
      data  => '0x00000000',
    }
  }

  if($harden_windows_server::ensure_configure_automatic_updates_is_set_to_enabled) {
    registry::value { 'NoAutoUpdate':
      key   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU',
      value => 'NoAutoUpdate',
      type  => 'dword',
      data  => '0x00000000',
    }
  }

  if($harden_windows_server::ensure_configure_automatic_updates_scheduled_install_day_is_set_to_0_every_day) {
    registry::value { 'ScheduledInstallDay':
      key   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU',
      value => 'ScheduledInstallDay',
      type  => 'dword',
      data  => '0x00000000',
    }
  }

  if($harden_windows_server::ensure_do_not_adjust_default_option_to_install_updates_and_shut_down_in_shut_down_windows_dialog_box_is_set_to_disabled) {
    registry::value { 'NoAUAsDefaultShutdownOption':
      key   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU',
      value => 'NoAUAsDefaultShutdownOption',
      type  => 'dword',
      data  => '0x00000000',
    }
  }

  if($harden_windows_server::ensure_do_not_display_install_updates_and_shut_down_option_in_shut_down_windows_dialog_box_is_set_to_disabled) {
    registry::value { 'NoAUShutdownOption':
      key   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU',
      value => 'NoAUShutdownOption',
      type  => 'dword',
      data  => '0x00000000',
    }
  }

  if($harden_windows_server::ensure_no_auto_restart_with_logged_on_users_for_scheduled_automatic_updates_installations_is_set_to_disabled) {
    registry::value { 'NoAutoRebootWithLoggedOnUsers':
      key   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU',
      value => 'NoAutoRebootWithLoggedOnUsers',
      type  => 'dword',
      data  => '0x00000000',
    }
  }

  if($harden_windows_server::ensure_reschedule_automatic_updates_scheduled_installations_is_set_to_enabled_1_minute) {
    registry::value { 'RescheduleWaitTimeEnabled':
      key   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU',
      value => 'RescheduleWaitTimeEnabled',
      type  => 'dword',
      data  => '0x00000001',
    }
    registry::value { 'RescheduleWaitTime':
      key   => 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU',
      value => 'RescheduleWaitTime',
      type  => 'dword',
      data  => '0x00000001',
    }
  }

  # Need to figure out how to make changes to each user on the system
  # if($harden_windows_server::ensure_enable_screen_saver_is_set_to_enabled) {
  #
  # }
  #
  # if($harden_windows_server::ensure_force_specific_screen_saver_screen_saver_executable_name_is_set_to_enabled_scrnsavescr) {
  #
  # }
  #
  # if($harden_windows_server::ensure_password_protect_the_screen_saver_is_set_to_enabled) {
  #
  # }
  #
  # if($harden_windows_server::ensure_screen_saver_timeout_is_set_to_enabled_900_seconds_or_fewer_but_not_0) {
  #
  # }
  #
  # if($harden_windows_server::ensure_turn_off_help_experience_improvement_program_is_set_to_enabled) {
  #
  # }
  #
  # if($harden_windows_server::ensure_do_not_preserve_zone_information_in_file_attachments_is_set_to_disabled) {
  #
  # }
  #
  # if($harden_windows_server::ensure_notify_antivirus_programs_when_opening_attachments_is_set_to_enabled) {
  #
  # }
  #
  # if($harden_windows_server::ensure_prevent_users_from_sharing_files_within_their_profile_is_set_to_enabled) {
  #
  # }
  #
  # if($harden_windows_server::ensure_always_install_with_elevated_privileges_is_set_to_disabled_windows_installer) {
  #
  # }
  #
  # if($harden_windows_server::ensure_prevent_codec_download_is_set_to_enabled) {
  #
  # }




}
