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

}
