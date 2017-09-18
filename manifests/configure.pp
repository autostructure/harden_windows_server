# Configuration Settings
class harden_windows_server::configure {
  include local_security_policy

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

  #2.2
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

  #need to add local account
  if($harden_windows_server::configure_deny_access_to_this_computer_from_the_network) {
    if($harden_windows_server::is_domain_controller) {
      local_security_policy { 'Deny access to this computer from the network':
        ensure         => 'present',
        policy_setting => 'SeDenyNetworkLogonRight',
        policy_type    => 'Privilege Rights',
        policy_value   => '*S-1-5-32-546',
      }
    } else {
      local_security_policy { 'Deny access to this computer from the network':
        ensure         => 'present',
        policy_setting => 'SeDenyNetworkLogonRight',
        policy_type    => 'Privilege Rights',
        policy_value   => '*S-1-5-32-546',
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

  #need to add local account
  if($harden_windows_server::ensure_deny_log_on_through_remote_desktop_services_to_include_guests_local_account) {
    local_security_policy { 'Deny log on through Remote Desktop Services':
      ensure         => 'present',
      policy_setting => 'SeDenyRemoteInteractiveLogonRight',
      policy_type    => 'Privilege Rights',
      policy_value   => '*S-1-5-32-546',
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

  #S-1-5-17 is only used when the Web Server (IIS) role is activated
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
        policy_value   => '*S-1-5-19,*S-1-5-20,*S-1-5-32-544,*S-1-5-6,*S-1-5-17',
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

  #Not supported by local_security_policy
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

  #Must choose a different name for Administrator
  if($harden_windows_server::configure_accounts_rename_administrator_account) {
    local_security_policy { 'Accounts: Rename administrator account':
      ensure         => 'present',
      policy_setting => 'NewAdministratorName',
      policy_type    => 'System Access',
      policy_value   => '"Administrator"',
    }
  }

  #Must choose a different name for Guest
  if($harden_windows_server::configure_accounts_rename_guest_account) {
    local_security_policy { 'Accounts: Rename guest account':
      ensure         => 'present',
      policy_setting => 'NewGuestName',
      policy_type    => 'System Access',
      policy_value   => '"Guest"',
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

  #Domain Controller not supported by local_security_policy
  #if($harden_windows_server::ensure_domain_controller_allow_server_operators_to_schedule_tasks_is_set_to_disabled) {

  #}

  #if($harden_windows_server::ensure_domain_controller_ldap_server_signing_requirements_is_set_to_require_signing) {

  #}

  #if($harden_windows_server::ensure_domain_controller_refuse_machine_account_password_changes_is_set_to_disabled) {

  #}

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

  #Choose a better text
  if($harden_windows_server::configure_interactive_logon_message_text_for_users_attempting_to_log_on) {
    local_security_policy { 'Interactive logon: Message text for users attempting to log on':
      ensure         => 'present',
      policy_setting => 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\LegalNoticeText',
      policy_type    => 'Registry Values',
      policy_value   => '7,Welcome!',
    }
  }

  #Choose a better text
  if($harden_windows_server::configure_interactive_logon_message_title_for_users_attempting_to_log_on) {
    local_security_policy { 'Interactive logon: Message title for users attempting to log on':
      ensure         => 'present',
      policy_setting => 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\LegalNoticeCaption',
      policy_type    => 'Registry Values',
      policy_value   => '1,"Title Bar"',
    }
  }

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

  #supposedly supported by local_security_policy but not showing up with puppet resource local_security_policy
  #if($harden_windows_server::ensure_microsoft_network_server_spn_target_name_validation_level_is_set_to_accept_if_provided_by_client) {
  #
  #}

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
    }
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

  #Not supported by local_security_policy module
  # if($harden_windows_server::ensure_network_security_allow_localsystem_null_session_fallback_is_set_to_disabled) {
  #
  # }
  #
  # if($harden_windows_server::ensure_network_security_allow_pku2u_authentication_requests_to_use_online_identities_is_set_to_disabled) {
  #
  # }
  #
  # if($harden_windows_server::ensure_network_security_configure_encryption_types_allow_for_kerberos) {
  #
  # }
  #
  # if($harden_windows_server::ensure_network_security_do_not_store_lan_manager_hash_value_on_next_password_change_is_set_to_enabled) {
  #
  # }

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

  if($harden_windows_server::ensure_audit_credential_validation_is_set_to_success_and_failure) {

  }

  if($harden_windows_server::ensure_audit_application_group_management_is_set_to_success_and_failure) {

  }

  if($harden_windows_server::ensure_audit_computer_account_management_is_set_to_success_and_failure) {

  }

  if($harden_windows_server::ensure_audit_distribution_group_management_is_set_to_success_and_failure) {
    if($harden_windows_server::is_domain_controller) {

    }
  }

  if($harden_windows_server::ensure_audit_other_account_management_events_is_set_to_success_and_failure) {

  }

  if($harden_windows_server::ensure_audit_security_group_management_is_set_to_success_and_failure) {

  }

  if($harden_windows_server::ensure_audit_user_account_management_is_set_to_success_and_failure) {

  }

  if($harden_windows_server::ensure_audit_process_creation_is_set_to_success) {

  }

  if($harden_windows_server::ensure_audit_directory_service_access_is_set_to_success_and_failure) {
    if($harden_windows_server::is_domain_controller) {
      local_security_policy { 'Audit directory service access':
        ensure         => 'present',
        policy_setting => 'AuditDSAccess',
        policy_type    => 'Event Audit',
        policy_value   => '0',
      }
    }
  }

  if($harden_windows_server::ensure_audit_directory_service_changes_is_set_to_success_and_failure) {
    if($harden_windows_server::is_domain_controller) {

    }
  }

  if($harden_windows_server::ensure_audit_account_lockout_is_set_to_success) {

  }

  if($harden_windows_server::ensure_audit_logoff_is_set_to_success) {

  }

  if($harden_windows_server::ensure_audit_logon_is_set_to_success_and_failure) {

  }

  if($harden_windows_server::ensure_audit_other_logon_logoff_events_is_set_to_success_and_failure) {

  }

  if($harden_windows_server::ensure_audit_special_logon_is_set_to_success) {

  }

  if($harden_windows_server::ensure_audit_audit_policy_change_is_set_to_success_and_failure) {

  }

  if($harden_windows_server::ensure_audit_authentication_policy_change_is_set_to_success) {

  }

  if($harden_windows_server::ensure_audit_sensitive_privilege_use_is_set_to_success_and_failure) {

  }

  if($harden_windows_server::ensure_audit_ipsec_driver_is_set_to_success_and_failure) {

  }

  if($harden_windows_server::ensure_audit_other_system_events_is_set_to_success_and_failure) {

  }

  if($harden_windows_server::ensure_audit_security_state_change_is_set_to_success) {

  }

  if($harden_windows_server::ensure_audit_security_system_extension_is_set_to_success_and_failure) {

  }

  if($harden_windows_server::ensure_audit_system_integrity_is_set_to_success_and_failure) {

  }



}
