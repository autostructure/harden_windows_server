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


}
