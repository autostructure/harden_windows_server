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


| |Control                                                                                                           | Enforced |   |     | Notes                                                            |
|-|------------------------------------------------------------------------------------------------------------------|----------|---|-----|------------------------------------------------------------------|
| |                                                                                                                  | Y        | N | N/A |                                                                  |
| | Level 1                                                                                                          |          |   |     |                                                                  |
| 1.1.1 | Ensure 'Enforce password history' is set to '24 or more password(s)'                                       | X        |   |     | 24 passwords                                                     |
| 1.1.2 | Ensure 'Maximum password age' is set to '60 or fewer days, but not 0'                                      | X        |   |     | 42 days                                                          |
| 1.1.3 | Ensure 'Minimum password age' is set to '1 or more day(s)'                                                 | X        |   |     | 1 day                                                            |
| 1.1.4 | Ensure 'Minimum password length' is set to '14 or more character(s)'                                       | X        |   |     | 14 characters                                                    |
| 1.1.5 | Ensure 'Password must meet complexity requirements' is set to 'Enabled'                                    | X        |   |     |                                                                  |
| 1.1.6 | Ensure 'Store passwords using reversible encryption' is set to 'Disabled'                                  | X        |   |     |                                                                  |
| 1.2.1 | Ensure 'Account lockout duration' is set to '15 or more minute(s)'                                         | X        |   |     | 30 minutes                                                       |
| 1.2.2 | Ensure 'Account lockout threshold' is set to '10 or fewer invalid logon attempt(s), but not 0'             | X        |   |     | 10 attempts                                                      |
| 1.2.3 | Ensure 'Reset account lockout counter after' is set to '15 or more minute(s)'                              | X        |   |     | 30 minutes                                                       |
| 2.2.1 | Ensure 'Acceess Credential Manager as a trusted calls' is set to 'No One'                                                                 | X        |   |     |                                                                  |
| 2.2.2 | Configure 'Access this computer from the network'                                                  | X        |   |     |                                                                  |
| 2.2.3 | Ensure 'Act as part of the operating system' is set to 'No One'                                                           | X        |   |     |                                                                  |
| 2.2.4 | Ensure 'Add workstations to domain' is set to 'Administrators' (DC only)                                                           | X        |   |     |                                                                  |
| 2.2.5 | Ensure 'Adjust memory quotas for a process' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE'                                                       | X        |   |     |                                                                  |
| 2.2.6 | Configure 'Allow log on locally'                                                | X        |   |     |                                                                  |
| 2.2.7 | Configure 'Allow log on through Remote Desktop Services'                                                          | X        |   |     |                                                                  |
| 2.2.8 | Ensure 'Back up files and directories' is set to 'Administrators'                                                      | X        |   |     |                                                                  |
| 2.2.9 | Ensure 'Change the system time' is set to 'Administrators, LOCAL SERVICE'                                                             | X        |   |     |                                                                  |
| 2.2.10 | Ensure 'Change the time zone' is set to 'Administrators, LOCAL SERVICE'                                                    | X        |   |     |                                                                  |
| 2.2.11 | Ensure 'Create a pagefile' is set to 'Administrators'                                                              | X        |   |     |                                                                  |
| 2.2.12 | Ensure 'Create a token object' is set to 'No One'                                                       | X        |   |     |                                                                  |
| 2.2.13 | Ensure 'Create global objects' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'                                                           | X        |   |     |                                                                  |
| 2.2.14 | Ensure 'Create permanent shared objects' is set to 'No One'                                                                         |          |   |     |                                                                  |
| 2.2.15 | Configure 'Create symbolic links'                                                                        |          |   | X   | Developer must determine if a connector is sensitive.            |
| 2.2.16 | Ensure 'Debug programs' is set to 'Administrators'                                                                  |          |   | X   | Developer must determine if connector is http or https           |
| 2.2.17 | Configure 'Deny access to this computer from the network'                                                |          |   |     |                                                                  |
| 2.2.18 | Ensure 'Deny log on as a batch job' to include 'Guests'                                              |          |   | X   | Developer must determine if a connector is secure.               |
| 2.2.19 | Ensure 'Deny log on as a service' to include 'Guests'                                                                      |          |   |     |                                                                  |
| 2.2.20 | Ensure 'Deny log on locally' to include 'Guests'                                                     | X        |   |     |                                                                  |
| 2.2.21 | Ensure 'Deny log on through Remote Desktop Services' to include 'Guests, Local account'                                                 | X        |   |     |                                                                  |
| 2.2.22 | Configure 'Enable computer and user accounts to be trusted for delegation'                                                             | X        |   |     |                                                                  |
| 2.2.23 | Ensure 'Force shutdown from a remote system' is set to 'Administrators'                                          | X        |   |     |                                                                  |
| 2.2.24 | Ensure 'Generate security audits' is set to 'LOCAL SERVICE, NETWORK SERVICE'                                                                                  |          |   |     |                                                                  |
| 2.2.25 | Configure 'Impersonate a client after authentication'                                               |          | X |     |                                                                  |
| 2.2.26 | Ensure 'Increase scheduling priority' is set to 'Administrators'                                                                                        |          |   |     |                                                                  |
| 2.2.27 | Ensure 'Load and unload device drivers' is set to 'Administrators'                                                                |          | X |     |                                                                  |
| 2.2.28 | Ensure 'Lock pages in memory' is set to 'No One'                                                        |          |   |     |                                                                  |
| 2.2.29 | Ensure 'Log on as a batch job' is set to 'Administrators' (DC ONLY)            |          | X |     |                                                                  |
| 2.2.30 | Configure 'Manage auditing and security log'                                                   |          |   | X   | Web manager application Is removed.                              |
| 2.2.31 | Ensure 'Modify an object label' is set to 'No One'                                                                    | X        |   |     |                                                                  |
| 2.2.32 | Ensure 'Modify firmware environment values' is set to 'Administrators'                                                                   | X        |   |     |                                                                  |
| 2.2.33 | Ensure 'Perform volume maintenance tasks' is set to 'Administrators'                                                                     | X        |   |     |                                                                  |
| 2.2.34 | Ensure 'Profile single process' is set to 'Administrators'                                                            | X        |   |     |                                                                  |
| 2.2.35 | Ensure 'Profile system performance' is set to 'Administrators, NT SERVICE\WdiServiceHost'                                                               | X        |   |     |                                                                  |
| 2.2.36 | Ensure 'Replace a process level token' is set to 'LOCAL SERVICE, NETWORK SERVICE'                                                                  | X        |   |     |                                                                  |
| 2.2.37 | Ensure 'Restore files and directories' is set to 'Administrators'                                                    | X        |   |     |                                                                  |
| 2.2.38 | Ensure 'Shut down the system' is set to 'Administrators'                                        |          | X |     |                                                                  |
| 2.2.39 | Ensure 'Synchronize directory service data' is set to 'No One' (DC ONLY) |          |   |     |                                                                  |
| 2.2.40 | Ensure 'Take ownership of files or other objects' is set to 'Administrators'                                                                                    |          |   |     |                                                                  |
| 1.2 | Disable Unused Connectors (Not Scored)                                                                       |          |   |     |                                                                  |
| 2 | Limit Server Platform Information Leaks                                                                         |          |   |     |                                                                  |
| 2.1 | Alter the Advertised server.info String (Scored)                                                             |          |   |     |                                                                  |
| 2.2  | Alter the Advertised server.number String (Scored)                                                           |          |   |     |                                                                  |
| 2.3  | Alter the Advertised server.built Date (Scored)                                                              |          |   |     |                                                                  |
| 2.4  |Disable X-Powered-By HTTP Header and Rename the Server Value for all Connectors (Scored)                     |          |   |     |                                                                  |
| 3.2  |Disable the Shutdown port (Not Scored)                                                                       |          |   |     |                                                                  |
| 5 | Configure Realms                                                                                                |          |   |     |                                                                  |
| 5.1  | Use secure Realms (Scored)                                                                                   |          |   |     |                                                                  |
| 5.2  | Use LockOut Realms (Scored)                                                                                  |          |   |     |                                                                  |
| 6 | Connector Security                                                                                              |          |   |     |                                                                  |
| 6.1 | Setup Client-cert Authentication (Scored)                                                                    |          |   |     |                                                                  |
| 7. |Establish and Protect Logging Facilities                                                                       |          |   |     |                                                                  |
| 7.1 |Application specific logging (Scored)                                                                         | X        |   |     |                                                                  |
| 7.3 |Ensure className is set correctly in context.xml (Scored)                                                     | X        |   |     |                                                                  |
| 7.7 |Configure log file size limit (Scored)                                                                        |          | X |     |                                                                  |
| 9. |Application Deployment                                                                                         |          |   |     |                                                                  |
| 9.2 |Disabling auto deployment of applications (Scored)                                                            |          | X |     |                                                                  |
| 9.3 |Disable deploy on startup of applications (Scored)                                                            |          | X |     |                                                                  |
| 10 |Miscellaneous Configuration Settings                                                                           |          |   |     |                                                                  |
| 10.2 |Restrict access to the web administration (Not Scored)                                                       |          | X |     |                                                                  |
| 10.3 |Restrict manager application (Not Scored)                                                                    |          |   | X   | Web manager application Is removed.                              |
| 10.5 |Rename the manager application (Scored)                                                                      |          |   | X   | Web manager application Is removed.                              |
| 10.8 |Do not allow additional path delimiters (Scored)                                                             |          | X |     |                                                                  |
| 10.9 |Do not allow custom header status messages (Scored)                                                          |          | X |     |                                                                  |
| 10.10 |Configure connectionTimeout (Scored)                                                                        |          | X |     |                                                                  |
| 10.11 |Configure maxHttpHeaderSize (Scored)                                                                        |          | X |     |                                                                  |
| 10.12 |Force SSL for all applications (Scored)                                                                     |          | X |     | This requires SSL to be configured; which may not be applicable. |
| 10.17 |Do not resolve hosts on logging valves (Scored)                                                             |          | X |     |                                                                  |


## Limitations

## Development
Future Release:
- Support more server versions
- Edit parameters with hiera
- Add more level 2 features
- Allow more customization

## Contributers
Jack Coleman <jack@autostructure.io>
