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




}
