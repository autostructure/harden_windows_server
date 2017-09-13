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

}
