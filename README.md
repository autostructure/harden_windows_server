# harden_windows_server

## Module Description
This module hardens Windows Server 2008 R2 to the most recent CIS Benchmark, which can be found here:

https://www.cisecurity.org/cis-benchmarks/

## Setup
To use this module, you need to specify whether or not the node is a **Domain Controller** or a **Member Server** by modifying the `is_domain_controller` parameter. The CIS Benchmark recommends a different security configuration for each type of node. This module defaults to the **Member Server** configuration.

Instantiate the class as a **Domain Controller**:

``` puppet
class { 'harden_windows_server':
  is_domain_controller => true,
}
```

Instantiate the class as a **Member Server**:

``` puppet
class { 'harden_windows_server':
  is_domain_controller => false,
}
```

## Usage
The CIS Benchmark has two types of security configurations: **Level 1** and **Level 2**.

**Level 1** items intend to:

- be practical and prudent;
- provide a clear security benefit; and
- not inhibit the utility of the technology beyond acceptable means.

**Level 2** items exhibit one or more of the following characteristics:

- are intended for environments or use cases where security is paramount
- acts as defense in depth measure
- may negatively inhibit the utility or performance of the technology

By default, all **Level 1** items are managed by the module. However, each organization is unique and might need to disable certain **Level 1** items so that they can configure them themselves. See our reference for a list of all managed items and disable them as shown below, if needed.

For example, the `ensure_account_lockout_duration_is_set_to_15_or_more_minutes` item sets the lockout duration to 30 minutes by default. If your organization requires a different lockout duration, disable this parameter so you can manually configure it. In a future release, you will be able to manage custom values within the module.

Disable `ensure_account_lockout_duration_is_set_to_15_or_more_minutes`:

``` puppet
class { 'harden_windows_server':
  is_domain_controller => false,
  ensure_account_lockout_duration_is_set_to_15_or_more_minutes => false,
}
```

**Level 2** items are not managed, by default. To enable a **Level 2** item, find the parameter in our reference and set it to `true`.

Enable `ensure_log_on_as_a_batch_job_is_set_to_administrators`:

``` puppet
class { 'harden_windows_server':
  is_domain_controller => false,
  ensure_log_on_as_a_batch_job_is_set_to_administrators => true,
}
```

## Reference

----------

### Level 1
| |Control                                                                                                           | Enforced |   |     | Notes                                                            |
|-|------------------------------------------------------------------------------------------------------------------|----------|---|-----|------------------------------------------------------------------|
| |                                                                                                                  | MS       | DC| N/A |                                                                  |
| 1.1.1 | Ensure 'Enforce password history' is set to '24 or more password(s)'                                       | X        | X |     | 24 passwords                                                     |
| 1.1.2 | Ensure 'Maximum password age' is set to '60 or fewer days, but not 0'                                      | X        | X |     | 42 days                                                          |
| 1.1.3 | Ensure 'Minimum password age' is set to '1 or more day(s)'                                                 | X        | X |     | 1 day                                                            |
| 1.1.4 | Ensure 'Minimum password length' is set to '14 or more character(s)'                                       | X        | X |     | 14 characters                                                    |
| 1.1.5 | Ensure 'Password must meet complexity requirements' is set to 'Enabled'                                    | X        | X |     |                                                                  |
| 1.1.6 | Ensure 'Store passwords using reversible encryption' is set to 'Disabled'                                  | X        | X |     |                                                                  |
| 1.2.1 | Ensure 'Account lockout duration' is set to '15 or more minute(s)'                                         | X        | X |     | 30 minutes                                                       |
| 1.2.2 | Ensure 'Account lockout threshold' is set to '10 or fewer invalid logon attempt(s), but not 0'             | X        | X |     | 10 attempts                                                      |
| 1.2.3 | Ensure 'Reset account lockout counter after' is set to '15 or more minute(s)'                              | X        | X |     | 30 minutes                                                       |
| 2.2.1 | Ensure 'Acceess Credential Manager as a trusted calls' is set to 'No One'                                  | X        | X |     |                                                                  |
| 2.2.2 | Configure 'Access this computer from the network'                                                          | X        | X |     |                                                                  |
| 2.2.3 | Ensure 'Act as part of the operating system' is set to 'No One'                                            | X        | X |     |                                                                  |
| 2.2.4 | Ensure 'Add workstations to domain' is set to 'Administrators' (DC only)                                   |          | X |     |                                                                  |
| 2.2.5 | Ensure 'Adjust memory quotas for a process' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE'     | X        | X |     |                                                                  |
| 2.2.6 | Configure 'Allow log on locally'                                                                           | X        | X |     |                                                                  |
| 2.2.7 | Configure 'Allow log on through Remote Desktop Services'                                                   | X        | X |     |                                                                  |
| 2.2.8 | Ensure 'Back up files and directories' is set to 'Administrators'                                          | X        | X |     |                                                                  |
| 2.2.9 | Ensure 'Change the system time' is set to 'Administrators, LOCAL SERVICE'                                  | X        | X |     |                                                                  |
| 2.2.10 | Ensure 'Change the time zone' is set to 'Administrators, LOCAL SERVICE'                                   | X        | X |     |                                                                  |
| 2.2.11 | Ensure 'Create a pagefile' is set to 'Administrators'                                                     | X        | X |     |                                                                  |
| 2.2.12 | Ensure 'Create a token object' is set to 'No One'                                                         | X        | X |     |                                                                  |
| 2.2.13 | Ensure 'Create global objects' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'        | X        | X |     |                                                                  |
| 2.2.14 | Ensure 'Create permanent shared objects' is set to 'No One'                                               | X        | X |     |                                                                  |
| 2.2.15 | Configure 'Create symbolic links'                                                                         | X        | X |     |                                                                  |
| 2.2.16 | Ensure 'Debug programs' is set to 'Administrators'                                                        | X        | X |     |                                                                  |
| 2.2.17 | Configure 'Deny access to this computer from the network'                                                 | X        | X |     |                                                                  |
| 2.2.18 | Ensure 'Deny log on as a batch job' to include 'Guests'                                                   | X        | X |     |                                                                  |
| 2.2.19 | Ensure 'Deny log on as a service' to include 'Guests'                                                     | X        | X |     |                                                                  |
| 2.2.20 | Ensure 'Deny log on locally' to include 'Guests'                                                          | X        | X |     |                                                                  |
| 2.2.21 | Ensure 'Deny log on through Remote Desktop Services' to include 'Guests, Local account'                   | X        | X |     |                                                                  |
| 2.2.22 | Configure 'Enable computer and user accounts to be trusted for delegation'                                | X        | X |     |                                                                  |
| 2.2.23 | Ensure 'Force shutdown from a remote system' is set to 'Administrators'                                   | X        | X |     |                                                                  |
| 2.2.24 | Ensure 'Generate security audits' is set to 'LOCAL SERVICE, NETWORK SERVICE'                              | X        | X |     |                                                                  |
| 2.2.25 | Configure 'Impersonate a client after authentication'                                                     | X        | X |     |                                                                  |
| 2.2.26 | Ensure 'Increase scheduling priority' is set to 'Administrators'                                          | X        | X |     |                                                                  |
| 2.2.27 | Ensure 'Load and unload device drivers' is set to 'Administrators'                                        | X        | X |     |                                                                  |
| 2.2.28 | Ensure 'Lock pages in memory' is set to 'No One'                                                          | X        | X |     |                                                                  |
| 2.2.29 | Ensure 'Log on as a batch job' is set to 'Administrators' (DC ONLY)                                       |          | X |     |                                                                  |
| 2.2.30 | Configure 'Manage auditing and security log'                                                              | X        | X |     |                                                                  |
| 2.2.31 | Ensure 'Modify an object label' is set to 'No One'                                                        | X        | X |     |                                                                  |
| 2.2.32 | Ensure 'Modify firmware environment values' is set to 'Administrators'                                    | X        | X |     |                                                                  |
| 2.2.33 | Ensure 'Perform volume maintenance tasks' is set to 'Administrators'                                      | X        | X |     |                                                                  |
| 2.2.34 | Ensure 'Profile single process' is set to 'Administrators'                                                | X        | X |     |                                                                  |
| 2.2.35 | Ensure 'Profile system performance' is set to 'Administrators, NT SERVICE\WdiServiceHost'                 | X        | X |     |                                                                  |
| 2.2.36 | Ensure 'Replace a process level token' is set to 'LOCAL SERVICE, NETWORK SERVICE'                         | X        | X |     |                                                                  |
| 2.2.37 | Ensure 'Restore files and directories' is set to 'Administrators'                                         | X        | X |     |                                                                  |
| 2.2.38 | Ensure 'Shut down the system' is set to 'Administrators'                                                  | X        | X |     |                                                                  |
| 2.2.39 | Ensure 'Synchronize directory service data' is set to 'No One' (DC ONLY)                                  |          | X |     |                                                                  |
| 2.2.40 | Ensure 'Take ownership of files or other objects' is set to 'Administrators'                              | X        | X |     |                                                                  |
| 2.3.1.1 | Ensure 'Accounts: Administrator account status' is set to 'Disabled'                                     | X        | X |     |                                                                  |
| 2.3.1.2 | Ensure 'Accounts: Guest account status' is set to 'Disabled'                                             | X        | X |     |                                                                  |
| 2.3.1.3 | Ensure 'Accounts: Limit local account use of blank passwords to console logon only' is set to 'Enabled'  | X        | X |     |                                                                  |
| 2.3.1.4 | Configure 'Accounts: Rename administrator account'                                                       | X        | X |     |                                                                  |
| 2.3.1.5 | Configure 'Accounts: Rename guest account' .                                                             | X        | X |     |                                                                  |
| 2.3.2.1 | Ensure 'Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings' is set to 'Enabled'| X        | X |     |                            |
| 2.3.2.2 | Ensure 'Audit: Shut down system immediately if unable to log security audits' is set to 'Disabled'       | X        | X |     |                                                                  |
| 2.3.4.1 | Ensure 'Devices: Allowed to format and eject removable media' is set to 'Administrators                  | X        | X |     |                                                                  |
| 2.3.4.2 | Ensure 'Devices: Prevent users from installing printer drivers' is set to 'Enabled'                      | X        | X |     |                                                                  |
| 2.3.5.1 | Ensure 'Domain controller: Allow server operators to schedule tasks' is set to 'Disabled' (DC ONLY)      |          | X |     |                                                                  |
| 2.3.5.2 | Ensure 'Domain controller: LDAP server signing requirements' is set to 'Require signing' (DC ONLY)       |          | X |     |                                                                  |
| 2.3.5.3 | Ensure 'Domain controller: Refuse machine account password changes' is set to 'Disabled' (DC ONLY)       |          | X |     |                                                                  |
| 2.3.6.1 | Ensure 'Domain member: Digitally encrypt or sign secure channel data (always)' is set to 'Enabled'       | X        | X |     |                                                                  |
| 2.3.6.2 | Ensure 'Domain member: Digitally encrypt secure channel data (when possible)' is set to 'Enabled'        | X        | X |     |                                                                  |
| 2.3.6.3 | Ensure 'Domain member: Digitally sign secure channel data (when possible)' is set to 'Enabled'           | X        | X |     |                                                                  |
| 2.3.6.4 | Ensure 'Domain member: Disable machine account password changes' is set to 'Disabled'                    | X        | X |     |                                                                  |
| 2.3.6.5 | Ensure 'Domain member: Maximum machine account password age' is set to '30 or fewer days, but not 0'     | X        | X |     |                                                                  |
| 2.3.6.6 | Ensure 'Domain member: Require strong (Windows 2000 or later) session key' is set to 'Enabled'           | X        | X |     |                                                                  |
| 2.3.7.1 | Ensure 'Interactive logon: Do not display last user name' is set to 'Enabled'                            | X        | X |     |                                                                  |
| 2.3.7.2 | Ensure 'Interactive logon: Do not require CTRL+ALT_DEL' is set to 'Disabled'                             | X        | X |     |                                                                  |
| 2.3.7.3 | Configure 'Interactive logon: Message text for users attempting to log on'                               |          |   |  X  |                                                                  |
| 2.3.7.4 | Configure 'Interactive logon: Message title for users attempting to log on'                              |          |   |  X  |                                                                  |
| 2.3.7.5 | Ensure 'Interactive logon: Number of previous logons to cache (in case domain controller is not available)' is set to '4 or fewer logons' (MS ONLY)| X        |   |     |                        |
| 2.3.7.6 | Ensure 'Interactive logon: Prompt user to change password before expiration' is set to 'between 5 and 14 days'| X        | X |     |                                                             |
| 2.3.7.7 | Ensure 'Interactive logon: Require Domain Controller Authentication to unlock workstation' is set to 'Enabled' (MS ONLY)| X        |   |     |                                                   |
| 2.3.7.8 | Ensure 'Interactive logon: Smart card removal behavior' is set to 'Lock Workstation' or higher           | X        | X |     |                                                                  |
| 2.3.8.1 | Ensure 'Microsoft network client: Disitally sign communications (always)' is set to 'Enabled'            | X        | X |     |                                                                  |
| 2.3.8.2 | Ensure 'Microsoft network client: Digitally sign communications (if server agrees)' is set to 'Enabled'  | X        | X |     |                                                                  |
| 2.3.8.3 | Ensure 'Microsoft network client: Send unencrypted password to third-party SMB servers' is set to 'Disabled'| X        | X |     |                                                               |
| 2.3.9.1 | Ensure 'Microsoft network server: Amount of idle time required before suspending session' is set to '15 or fewer minutes, but not 0'| X        | X |     |                                       |
| 2.3.9.2 | Ensure 'Microsoft network server: Digitally sign communications (always)' is set to 'Enabled'            | X        | X |     |                                                                  |
| 2.3.9.3 | Ensure 'Microsoft network server: Digitally sign communications (if client agrees)' is set to 'Enabled'  | X        | X |     |                                                                  |
| 2.3.9.4 | Ensure 'Microsoft network server: Disconnect clients when logon hours expire' is set to 'Enabled         | X        | X |     |                                                                  |
| 2.3.9.5 | Ensure 'Microsoft network server: Server SPN target name validation level' is set to 'Accept if provided by client' or higher (MS ONLY)| X        |   |     |                                    |
| 2.3.10.1 | Ensure 'Network access: Allow anonymous SID/Name translation' is set to 'Disabled'                      | X        | X |     |                                                                  |
| 2.3.10.2 | Ensure 'Network access: Do not allow anonymous enumeration of SA accounts' is set to 'Enabled' (MS ONLY)| X        |   |     |                                                                  |
| 2.3.10.3 | Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts and shared' is set to 'Enabled' (MS ONLY)| X        |   |     |                                                      |
| 2.3.10.4 | Ensure 'Network access: Do not allow storage of passwords and credentials for network authentication' is set to 'Enabled'| X        | X |     |                                                 |
| 2.3.10.5 | Ensure 'Network access: Let Everyone permissions apply to anonymous users' is set to 'Disabled'         | X        | X |     |                                                                  |
| 2.3.10.6 | Configure 'Network access: Named Pipes that can be accessed anonymously'                                | X        | X |     |                                                                  |
| 2.3.10.7 | Configure 'Network access: Remotely accessible registry paths'                                          | X        | X |     |                                                                  |
| 2.3.10.8 | Configure 'Network access: Remotely accessible registry paths and sub-paths'                            | X        | X |     |                                                                  |
| 2.3.10.9 | Ensure 'Network access: Restrict anonymous access to Named Pipes and Shares' is set to 'Enabled'        | X        | X |     |                                                                  |
| 2.3.10.10 | Ensure 'Network access: Shares that can be accessed anonymously' is set to 'None'                      | X        | X |     |                                                                  |
| 2.3.10.11 | Ensure 'Network access: Sharing and security model for local accounts' is set to 'Classic - local users authenticate as themselves'| X        | X |     |                                      |
| 2.3.11.1 | Ensure 'Network security: Allow Local System to use computer identity for NTLM' is set to 'Enabled'     | X        | X |     |                                                                  |
| 2.3.11.2 | Ensure 'Network security: Allow LocalSystem NULL session fallback' is set to 'Disabled'                 | X        | X |     |                                                                  |
| 2.3.11.3 | Ensure 'Network security: Allow PKU2U authentication requests to this computer to use online identities' is set to 'Disabled| X        | X |     |                                              |
| 2.3.11.4 | Ensure 'Network security: Configure encryption types allowed for Kerberos' is set to 'RC4_HMAC_MD5, AES128_HMAC_SHA1, AES256_HMAC_SHA1, Future encryption types'| X        | X |     |          |
| 2.3.11.5 | Ensure 'Network security: Do not store LAN Manager hash value on next password change' is set to 'Enabled'| X        | X |     |                                                                |
| 2.3.11.6 | Ensure 'Network security: Force logoff when logon hours expire' is set to 'Enabled'                     | X        | X |     |                                                                  |
| 2.3.11.7 | Ensure 'Network security: LAN Manager authenticatioin level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'| X        | X |     |                                                      |
| 2.3.11.8 | Ensure 'Network security: LDAP client signing requirements' is set to 'Negotiate signing' or higher     | X        | X |     |                                                                  |
| 2.3.11.9 | Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) clients' is set to 'Require NTLMv2 session security, Require 128-bit encryption'| X        | X |     ||
| 2.3.11.10 | Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) servers' is set to 'Require NTLMv2 session security, Require 128-bit encryption'| X        | X |     ||
| 2.3.13.1 | Ensure 'Shutdown: Allow system to be shut down without having to log on' is set to 'Disabled'           | X        | X |     |                                                                  |
| 2.3.15.1 | Ensure 'System objects: Require case insensitivity for non-Windows subsystems' is set to 'Enabled'      | X        | X |     |                                                                  |
| 2.3.15.2 | Ensure 'System objects: Strengthen default permissions of internal system objects (e.g. Symbolic Links)' is set to 'Enabled'| X        | X |     |                                              |
| 2.3.16.1 | Ensure 'System settings: Optional subsystems' is set to 'Defined: (blank)' .                            | X        | X |     |                                                                  |
| 2.3.17.1 | Ensure 'User Account Control: Admin Apprival Mode for the Built-in Administrator account' is set to 'Enabled'| X        | X |     |                                                             |
| 2.3.17.2 | Ensure 'User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop' is set to 'Disabled'| X        | X |     |                                  |
| 2.3.17.3 | Ensure 'User Account Control: Behavrior of the elevation prompt for administrators in Admin Approval Mode' is set to 'Prompt for consent on the secure desktop'| X        | X |     |           |
| 2.3.17.4 | Ensure 'User Accounc Control: Behavior of the elevation prompt for standard users' is set to 'Automatically deny elevation requests'| X        | X |     |                                      |
| 2.3.17.5 | Ensure 'User Account Control: Detect application installations and prompt for elevation' is set to 'Enabled'| X        | X |     |                                                              |
| 2.3.17.6 | Ensure 'User Account Control: Only elevate UIAccess applications that are installed in secure locations' is set to 'Enabled'| X        | X |     |                                              |
| 2.3.17.7 | Ensure 'User Account Control: Run all administrators in Admin Approval Mode' is set to 'Enabled'        | X        | X |     |                                                                  |
| 2.3.17.8 | Ensure 'User Account Control: Switch to the secure desktop when prompting for elevation' is set to 'Enabled'| X        | X |     |                                                              |
| 2.3.17.9 | Ensure 'User Account Control: Virtualize file and registry write failures to per-user locations' is set to 'Enabled'| X        | X |     |                                                      |
| 9.1.1 | Ensure 'Windows Firewall: Domain: Firewall state' is set to 'On (recommended)'                          | X        | X |     |                                                                     |
| 9.1.2 | Ensure 'Windows Firewall: Domain: Inbound connections' is set to 'Block (default)'                      | X        | X |     |                                                                     |
| 9.1.3 | Ensure 'Windows Firewall: Domain: Outbound connections' is set to 'Allow (default)'                     | X        | X |     |                                                                     |
| 9.1.4 | Ensure 'Windows Firewall: Domain: Settings: Display a notification' is set to 'No'                      | X        | X |     |                                                                     |
| 9.1.5 | Ensure 'Windows Firewall: Domain: Settings: Apply local firewall rules' is set to 'Yes (default)'       | X        | X |     |                                                                     |
| 9.1.6 | Ensure 'Windows Firewall: Domain: Settings: Apply local connection security rules' is set to 'Yes (default)'| X        | X |     |                                                                 |
| 9.1.7 | Ensure 'Windows Firewall: Domain: Logging: Name' is set to '%SYSTEMROOT%\System32\logfiles\firewall\domainfw.log'| X        | X |     |                                                            |
| 9.1.8 | Ensure 'Windows Firewall: Domain: Logging: Size limit (KB)' is set to '16,384 KB or greater'            | X        | X |     |                                                                     |
| 9.1.9 | Ensure 'Windows Firewall: Domain: Logging: Log dropped packets' is set to 'Yes'                         | X        | X |     |                                                                     |
| 9.1.10 | Ensure 'Windows Firewall: Domain: Logging: Log successful connections' is set to 'Yes'                 | X        | X |     |                                                                     |
| 9.2.1 | Ensure 'Windows Firewall: Private: Firewall state' is set to 'On (recommended)'                         | X        | X |     |                                                                     |
| 9.2.2 | Ensure 'Windows Firewall: Private: Inbound connections' is set to 'Block (default)'                     | X        | X |     |                                                                     |
| 9.2.3 | Ensure 'Windows Firewall: Private: Outbound connections' is set to 'Allow (default)'                    | X        | X |     |                                                                     |
| 9.2.4 | Ensure 'Windows Firewall: Private: Settings: Display a notification' is set to 'No'                     | X        | X |     |                                                                     |
| 9.2.5 | Ensure 'Windows Firewall: Private: Settings: Apply local firewall rules' is set to 'Yes (default)'      | X        | X |     |                                                                     |
| 9.2.6 | Ensure 'Windows Firewall: Private: Settings: Apply local connection security rules' is set to 'Yes (default)'| X        | X |     |                                                                |
| 9.2.7 | Ensure 'Windows Firewall: Private: Logging: Name' is set to '%SYSTEMROOT%\System32\logfiles\firewall\privatefw.log'| X        | X |     |                                                          |
| 9.2.8 | Ensure 'Windows Firewall: Private: Logging: Size limit (KB)' is set to '16,384 KB or greater'           | X        | X |     |                                                                     |
| 9.2.9 | Ensure 'Windows Firewall: Private: Logging: Log dropped packets' is set to 'Yes'                        | X        | X |     |                                                                     |
| 9.2.10 | Ensure 'Windows Firewall: Private: Logging: Log successful connections' is set to 'Yes'                | X        | X |     | | 2.3.17.7 | Ensure 'Windows Firewall: Domain: Firewall state' is set to 'On (recommended)'| X        | X |     ||
| 9.3.1 | Ensure 'Windows Firewall: Public: Firewall state' is set to 'On (recommended)'                          | X        | X |     |                                                                     |
| 9.3.2 | Ensure 'Windows Firewall: Public: Inbound connections' is set to 'Block (default)'                      | X        | X |     |                                                                     |
| 9.3.3 | Ensure 'Windows Firewall: Public: Outbound connections' is set to 'Allow (default)'                     | X        | X |     |                                                                     |
| 9.3.4 | Ensure 'Windows Firewall: Public: Settings: Display a notification' is set to 'Yes'                     | X        | X |     |                                                                     |
| 9.3.5 | Ensure 'Windows Firewall: Public: Settings: Apply local firewall rules' is set to 'No'                  | X        | X |     |                                                                     |
| 9.3.6 | Ensure 'Windows Firewall: Public: Settings: Apply local connection security rules' is set to 'No'       | X        | X |     |                                                                     |
| 9.3.7 | Ensure 'Windows Firewall: Public: Logging: Name' is set to '%SYSTEMROOT%\System32\logfiles\firewall\publicfw.log'| X        | X |     |                                                            |
| 9.3.8 | Ensure 'Windows Firewall: Public: Logging: Size limit (KB)' is set to '16,384 KB or greater'            | X        | X |     |                                                                     |
| 9.3.9 | Ensure 'Windows Firewall: Public: Logging: Log dropped packets' is set to 'Yes'                         | X        | X |     |                                                                     |
| 9.3.10 | Ensure 'Windows Firewall: Public: Logging: Log successful connections' is set to 'Yes'                 | X        | X |     |                                                                     |
| 17.x.x | Advanced Audit Policy Configuration                                                                    |          |   |  X  |  Support coming soon                                                |
| 18.2.x | LAPS                                                                                                   |          |   |  X  |  Support coming soon                                                |
| 18.3.x | MSS (Legacy)                                                                                           |          |   |  X  |  Support coming soon                                                |
| 18.4.11.2 | Ensure 'Prohibit installation and configuration of Network Bridge on your DNS domain network' is set to 'Enabled'| X        | X |     |                                                        |
| 18.4.11.3 | Ensure 'Require domain users to elevate when setting a network's location' is set to 'Enabled'      | X        | X |     |                                                                     |
| 18.4.14.1 | Ensure 'Hardened UNC Paths' is set to 'Enabled, with "Require Mutual Authentication" and "Require Integrity" set for all NETLOGON and SYSVOL shares'|          |   |  X  |  Support coming soon|
| 18.4.19.2.1 | Disable IPv6 (Ensure TCPIP6 Parameter 'DisabledComponents' is set to '0xff (255)')                |          |   |  X  |  Support coming soon                                                |
| 18.6.1 | Ensure 'Apply UAC restrictions to local accounts on network logons' is set to 'Enabled' (MS ONLY)      |          |   |  X  |  Support coming soon                                                |
| 18.6.2 | Ensure 'WDigest Authentication' is set to 'Disabled'                                                   |          |   |  X  |  Support coming soon                                                |
| 18.8.3.1 | Ensure 'Include command line in process creation events' is set to 'Disabled'                        |          |   |  X  |  Support coming soon                                                |
| 18.8.6.2 | Ensure 'Allow remote access to the Plug and Play interface' is set to 'Disabled'                     | X        | X |     |                                                                     |
| 18.8.19.2 | Ensure 'configure registry policy processing: Do not apply during periodic background processing' is set to 'Enabled: FALSE'| X        | X |     |                                             |
| 18.8.19.3 | Ensure 'Configure registry policy processing: Process even if the Group Policy objects have not changed' is set to 'Enabled: TRUE'| X        | X |     |                                       |
| 18.8.19.4 | Ensure 'Turn off background refresh of Group Policy' is set to 'Disabled'                           |          |   | X   |  Support coming soon                                                |
| 18.8.20.1.x | Internet Communication Settings                                                                   |          |   | X   |  Support coming soon                                                |
| 18.8.25.1 | Ensure 'Always use classic logon' is set to 'Enabled' (MS ONLY)                                     | X        |   |     |                                                                     |
| 18.8.31.1 | Ensure 'Configure Offer Remote Assistance' is set to 'Disabled'                                     | X        | X |     |                                                                     |
| 18.8.31.2 | Ensure 'Configure Solicited Remote Assistance' is set to 'Disabled'                                 | X        | X |     |                                                                     |
| 18.8.32.1 | Ensure 'Enable RPC Endpoint Mapper Client Authentication' is set to 'Enabled' (MS ONLY)             | X        |   |     |                                                                     |
| 18.9.8.1 | Ensure 'Disallow Autoplay for non-volume devices' is set to 'Enabled'                                | X        | X |     |                                                                     |
| 18.9.8.2 | Ensure 'set the default behavior for AutoRun' is set to 'Enabled: Do not execute any autorun commands'| X        | X |     |                                                                    |
| 18.9.8.3 | Ensure 'Turn off Autoplay' is set to 'Enabled: All drives'                                           | X        | X |     |                                                                     |
| 18.9.15.1 | Ensure 'Do not display the password reveal button' is set to 'Enabled'                              |          |   | X   | Support coming soon                                                 |
| 18.9.15.2 | Ensure 'Enumerate administrator accounts on elevation' is set to 'Disabled'                         | X        | X |     |                                                                     |
| 18.9.18.1 | Ensure 'Turn off desktop gadgets' is set to 'Enabled'                                               | X        | X |     |                                                                     |
| 18.9.18.2 | Ensure 'Turn off user-installed desktop gadgets' is set to 'Enabled'                                | X        | X |     |                                                                     |
| 18.9.24.x | EMET                                                                                                |          |   | X   | Support coming soon                                                 |
| 18.9.26.1.1 | Ensure 'Application: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'| X        | X |     |                                                       |
| 18.9.26.1.2 | Ensure 'Application: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'| X        | X |     |                                                                    |
| 18.9.26.2.1 | Ensure 'Security: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'| X        | X |     |                                                          |
| 18.9.26.2.2 | Ensure 'Security: Specify the maximum log file size (KB)' is set to 'Enabled: 196,608 or greater' | X        | X |     |                                                                     |
| 18.9.26.3.1 | Ensure 'Setup: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'| X        | X |     |                                                             |
| 18.9.26.3.2 | Ensure 'Setup: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'     | X        | X |     |                                                                     |
| 18.9.26.4.1 | Ensure 'System: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'| X        | X |     |                                                            |
| 18.9.26.4.2 | Ensure 'System: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'    | X        | X |     |                                                                     |
| 18.9.30.2 | Ensure 'Turn off Data Execution Prevention for Explorer' is set to 'Disabled'                       | X        | X |     |                                                                     |
| 18.9.30.3 | Ensure 'Turn off heap termination on corruption' is set to 'Disabled'                               | X        | X |     |                                                                     |
| 18.9.30.4 | Ensure 'Turn off shell protocol protected mode' is set to 'Disabled'                                | X        | X |     |                                                                     |
| 18.9.47.1 | Ensure 'Prevent the usage of OneDrive for file storage' is set to 'Enabled'                         |          |   | X   | Support coming soon                                                 |
| 18.9.47.2 | Ensure 'Prevent the usage of OneDrive for file storage on Windows 8.1' is set to 'Enabled'          |          |   | X   | Support coming soon                                                 |
| 18.9.52.2.2 | Ensure 'Do not allow passwords to be saved' is set to 'Enabled'                                   | X        | X |     |                                                                     |
| 18.9.52.3.3.2 | Ensure 'Do not allow drive redirection' is set to 'Enabled'                                     | X        | X |     |                                                                     |
| 18.9.52.3.9.1 | Ensure 'Always prompt for password upon connection' is set to 'Enabled'                         | X        | X |     |                                                                     |
| 18.9.52.3.9.2 | Ensure 'Require secure RPC communication' is set to 'Enabled'                                   | X        | X |     |                                                                     |
| 18.9.52.3.9.3 | Ensure 'Set client connection encryption level' is set to 'Enabled: High Level'                 | X        | X |     |                                                                     |
| 18.9.52.3.11.1 | Ensure 'Do not delete temp folders upon exit' is set to 'Disabled'                             | X        | X |     |                                                                     |
| 18.9.52.3.11.2 | Ensure 'Do not use temporary folders per session' is set to 'Disabled'                         | X        | X |     |                                                                     |
| 18.9.53.1 | Ensure 'Prevent downloading of enclosures' is set to 'Enabled'                                      | X        | X |     |                                                                     |
| 18.9.54.2 | Ensure 'Allow indexing of encrypted files' is set to 'Disabled'                                     |          |   | X   | Support coming soon                                                 |
| 18.9.70.2.1 | Ensure 'Configure Default consent' is set to 'Enabled: Always ask before sending data'            | X        | X |     |                                                                     |
| 18.9.74.1 | Ensure 'Allow user control over installs' is set to 'Disabled'                                      | X        | X |     |                                                                     |
| 18.9.74.2 | Ensure 'Always install with elevated privileges' is set to 'Disabled'                               | X        | X |     |                                                                     |
| 18.9.84.1 | Ensure 'Turn on PowerShell Script Block Logging' is set to 'Disabled'                               |          |   | X   | Support coming soon                                                 |
| 18.9.84.2 | Ensure 'Turn on PowerShell Transcription' is set to 'Disabled'                                      |          |   | X   | Support coming soon                                                 |
| 18.9.86.1.1 | Ensure 'Allow Basic authentication' is set to 'Disabled'                                          | X        | X |     |                                                                     |
| 18.9.86.1.2 | Ensure 'Allow unencrypted traffic' is set to 'Disabled'                                           | X        | X |     |                                                                     |
| 18.9.86.1.3 | Ensure 'Disallow Digest authentication' is set to 'Enabled'                                       | X        | X |     |                                                                     |
| 18.9.86.2.1 | Ensure 'Allow Basic authentication' is set to 'Disabled'                                          | X        | X |     |                                                                     |
| 18.9.86.2.3 | Ensure 'Allow unencrypted traffic' is set to 'Disabled'                                           | X        | X |     |                                                                     |
| 18.9.86.2.4 | Ensure 'Disallow WinRM from storing RunAs credentials' is set to 'Enabled'                        |          |   | X   | Support coming soon                                                 |
| 18.9.90.2 | Ensure 'Configure Automatic Updates' is set to 'Enabled'                                            | X        | X |     |                                                                     |
| 18.9.90.3 | Ensure 'Configure Automatic Updates: Schedule install day' is set to '0 - Every day'                | X        | X |     |                                                                     |
| 18.9.90.4 | Ensure 'Do not adjust default option to 'Install Updates and Shut Down' in Shut Down Windows dialog box' is set to 'Disabled'| X        | X |     |                                            |
| 18.9.90.5 | Ensure 'Do not display 'Install Updates and Shut Down' option in Shut Down Windows dialog box' is set to 'Disabed'| X        | X |     |                                                       |
| 18.9.90.6 | Ensure 'No auto-restart with logged on users for scheduled automatic updates installations' is set to 'Disabled'| X        | X |     |                                                         |
| 18.9.90.7 | Ensure 'Reschedule Automatic Updates scheduled installations' is set to 'Enabled: 1 minute'         | X        | X |     |                                                                     |
| 19.x.x.x.x | Administrative Templates (User)                                                                    |          |   | X   | Support coming soon                                                 |



### Level 2
| |Control                                                                                                           | Enforced |   |     | Notes                                                            |
|-|------------------------------------------------------------------------------------------------------------------|----------|---|-----|------------------------------------------------------------------|
| |                                                                                                                  | MS       | DC| N/A |                                                                  |
| 18.4.9.1 | Ensure 'Turn on Mapper I/O (LLTDIO) driver' is set to 'Disabled'                                        | X        | X |     |                                                                  |
| 18.4.9.2 | Ensure 'Turn on Responder (RSPNDR) driver' is set to 'Disabled'                                         | X        | X |     |                                                                  |
| 18.4.10.2 | Ensure 'Turn off Microsoft Peer-to-Peer Networking Services' is set to 'Enabled'                       | X        | X |     |                                                                  |
| 18.4.20.1 | Ensure 'Configuration of wireless settings using Windows Connect Now' is set to 'Disabled'             | X        | X |     |                                                                  |
| 18.4.20.2 | Ensure 'Prohibit access of the Windows Connect Now wizards' is set to 'Enabled'                        | X        | X |     |                                                                  |
| 18.8.29.5.1 | Ensure 'Require a password when a computer wakes (on battery)' is set to 'Enabled'                   |          |   | X   | Support coming soon                                              |
| 18.8.29.5.2 | Ensure 'Require a password when a computer wakes (plugged in)' is set to 'Enabled                    |          |   | X   | Support coming soon                                              |
| 18.8.32.2 | Ensure 'Restrict Unauthenticated RPC clients' is set to 'Enabled: Authenticated' (MS ONLY)             |          |   | X   | Support coming soon                                              |
| 18.8.39.5.1 | Ensure 'Microsoft Support Diagnostic Tool: Turn on MSDT interactive communication with support provider' is set to 'Disabled'|          |   | X   | Support coming soon                      |
| 18.8.39.11.1 | Ensure 'Enable/Disable PerfTrack' is set to 'Disabled'                                              |          |   | X   | Support coming soon                                              |
| 18.8.44.1.1 | Ensure 'Enable Windows NTP Client' is set to 'Enabled'                                               |          |   | X   | Support coming soon                                              |
| 18.8.44.1.2 | Ensure 'Enable Windows NTP Server' is set to 'Disabled' (MS ONLY)                                    |          |   | X   | Support coming soon                                              |
| 18.9.37.1 | Ensure 'Turn off location' is set to 'Enabled'                                                         | X        | X |     |                                                                  |
| 18.9.52.3.2.1 | Ensure 'Restrict Remote Desktop Services users to a single Remote Desktop Services session' is set to 'Enabled'| X        | X |     |                                                      |
| 18.9.52.3.3.1 | Ensure 'Do not allow COM port redirection' is set to 'Enabled'                                     | X        | X |     |                                                                  |
| 18.9.52.3.3.3 | Ensure 'Do not allow LPT port redirection' is set to 'Enabled'                                     | X        | X |     |                                                                  |
| 18.9.52.3.3.4 | Ensure 'Do not allow supported Plug and Play device redirection' is set to 'Enabled'               | X        | X |     |                                                                  |
| 18.9.52.3.10.1 | Ensure 'Set time limit for active but idle Remote Desktop Services sessions' is set to 'Enabled: 15 minutes or less'| X        | X |     |                                                |
| 18.9.52.3.10.2 | Ensure 'Set time limit for disconnected sessions' is set to 'Enabled: 1 minute'                   | X        | X |     |                                                                  |
| 18.9.69.3.1 | Ensure 'Join Microsoft MAPS' is set to 'Disabled'                                                    |          |   | X   | Support coming soon                                              |
| 18.9.74.3 | Ensure 'Prevent Internet Explorer security prompt for Windows Installer scripts' is set to 'Disabled'  | X        | X |     |                                                                  |
| 18.9.86.2.2 | Ensure 'Allow remote server management through WinRM' is set to 'Disabled'                           |          |   | X   | Support coming soon                                              |
| 18.9.87.1 | Ensure 'Allow Remote Shell Access' is set to 'Disabled'                                                | X        | X |     |                                                                  |


## Limitations

## Development
Future Release:
- Support more server versions
- Edit parameters with hiera
- Add more level 2 features
- Allow more customization

## Contributers
Jack Coleman <jack@autostructure.io>
