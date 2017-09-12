#init.pp
class harden_windows_server (
  #a million parameters go here
  Boolean $ensure_enforce_password_history_is_set_to_24_or_more_passwords = true,
  Boolean $ensure_maximum_password_age_is_set_to_60_or_fewer_days_but_not_0 = true,
  Boolean $ensure_minimum_password_age_is_set_to_1_or_more_days = true,
  Boolean $ensure_minimum_password_length_is_set_to_14_or_more_characters = true,
  Boolean $ensure_password_must_meet_complexity_requirements_is_set_to_enabled = true,
  Boolean $ensure_store_passwords_using_reversible_encryption_is_set_to_disabled = true,
  Boolean $ensure_account_lockout_duration_is_set_to_15_or_more_minutes = true,
  Boolean $ensure_account_lockout_threshold_is_set_to_10_or_fewer_invalid_logon_attempts_but_not_0 = true,
  Boolean $ensure_reset_account_lockout_counter_after_is_set_to_15_or_more_minutes = true,
  ) {

  include harden_windows_server::configure
}
