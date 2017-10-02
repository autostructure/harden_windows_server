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
|                                                                                                                    | Y        | N | N/A |                                                                  |
| | Level 1                                                                                                          |          |   |     |                                                                  |
| 1.1.1 | Ensure 'Enforce password history' is set to '24 or more password(s)'                                       | X        |   |     | 24                                                               |
| 1.1.2 | Ensure 'Maximum password age' is set to '60 or fewer days, but not 0'                                      | X        |   |     | 42                                                               |
| 1.1.3 | Ensure 'Minimum password age' is set to '1 or more day(s)'                                                 | X        |   |     | 1                                                                |
| 1.1.4 | Ensure 'Minimum password length' is set to '14 or more character(s)'                                       | X        |   |     | 14                                                               |
| 1.1.5 | Ensure 'Password must meet complexity requirements' is set to 'Enabled'                                    | X        |   |     |                                                                  |
| 1.1.6 | Ensure 'Store passwords using reversible encryption' is set to 'Disabled'                                  | X        |   |     |                                                                  |
| 1.2.1 | Ensure 'Account lockout duration' is set to '15 or more minute(s)'                                         | X        |   |     | 30                                                               |
| 1.2.2 | Ensure 'Account lockout threshold' is set to '10 or fewer invalid logon attempt(s), but not 0'             | X        |   |     | 10                                                               |
| 1.2.3 | Ensure 'Reset account lockout counter after' is set to '15 or more minute(s)'                              | X        |   |     | 30                                                               |
| 4.2  | Restrict access to $CATALINA_BASE (Scored)                                                                  | X        |   |     |                                                                  |
| 4.3  | Restrict access to Tomcat configuration directory (Scored)                                                  | X        |   |     |                                                                  |
| 4.4  | Restrict access to Tomcat logs directory (Scored)                                                           | X        |   |     |                                                                  |
| 4.5  | Restrict access to Tomcat temp directory (Scored)                                                           | X        |   |     |                                                                  |
| 4.6  | Restrict access to Tomcat binaries directory (Scored)                                                       | X        |   |     |                                                                  |
| 4.7  | Restrict access to Tomcat web application directory (Scored)                                                | X        |   |     |                                                                  |
| 4.8  | Restrict access to Tomcat catalina.policy (Scored)                                                          | X        |   |     |                                                                  |
| 4.9  | Restrict access to Tomcat catalina.properties (Scored)                                                      | X        |   |     |                                                                  |
| 4.10 |  Restrict access to Tomcat context.xml (Scored)                                                             | X        |   |     |                                                                  |
| 4.11 | Restrict access to Tomcat logging.properties (Scored)                                                       | X        |   |     |                                                                  |
| 4.12 | Restrict access to Tomcat server.xml (Scored)                                                               | X        |   |     |                                                                  |
| 4.13 | Restrict access to Tomcat tomcat-users.xml (Scored)                                                         | X        |   |     |                                                                  |
| 4.14 | Restrict access to Tomcat web.xml (Scored)                                                                  | X        |   |     |                                                                  |
| 6 |Connector Security                                                                                              |          |   |     |                                                                  |
| 6.2 | Ensure SSLEnabled is set to True for Sensitive Connectors (Not Scored)                                       |          |   | X   | Developer must determine if a connector is sensitive.            |
| 6.3 | Ensure scheme is set accurately (Scored)                                                                     |          |   | X   | Developer must determine if connector is http or https           |
| 6.4 | Ensure secure is set to true only for SSL-enabled Connectors                                                 |          |   |     |                                                                  |
| 6.5 |Ensure SSL Protocol is set to TLS for Secure Connectors (Scored)                                              |          |   | X   | Developer must determine if a connector is secure.               |
| 7. |Establish and Protect Logging Facilities                                                                       |          |   |     |                                                                  |
| 7.2 |Specify file handler in logging.properties files (Scored)                                                     | X        |   |     |                                                                  |
| 7.4 |Ensure directory in context.xml is a secure location (Scored)                                                 | X        |   |     |                                                                  |
| 7.5 |Ensure pattern in context.xml is correct (Scored)                                                             | X        |   |     |                                                                  |
| 7.6 |Ensure directory in logging.properties is a secure location (Scored)                                          | X        |   |     |                                                                  |
| 8. |Configure Catalina Policy                                                                                      |          |   |     |                                                                  |
| 8.1 |Restrict runtime access to sensitive packages (Scored)                                                        |          | X |     |                                                                  |
| 9. |Application Deployment                                                                                         |          |   |     |                                                                  |
| 9.1 |Starting Tomcat with Security Manager (Scored)                                                                |          | X |     |                                                                  |
| 10 |Miscellaneous Configuration Settings                                                                           |          |   |     |                                                                  |
| 10.1 |Ensure Web content directory is on a separate partition from the Tomcat system files (Not Scored)            |          | X |     |                                                                  |
| 10.4 |Force SSL when accessing the manager application (Scored)                                                    |          |   | X   | Web manager application Is removed.                              |
| 10.6 |Enable strict servlet Compliance (Scored)                                                                    | X        |   |     |                                                                  |
| 10.7 |Turn off session facade recycling (Scored)                                                                   | X        |   |     |                                                                  |
| 10.14 |Do not allow symbolic linking (Scored)                                                                      | X        |   |     |                                                                  |
| 10.15 |Do not run applications as privileged (Scored)                                                              | X        |   |     |                                                                  |
| 10.16 |Do not allow cross context requests (Scored)                                                                | X        |   |     |                                                                  |
| 10.18 |Enable memory leak listener (Scored)                                                                        | X        |   |     |                                                                  |
| 10.19 |Setting Security Liftcycle Listener (Scored)                                                                | X        |   |     |                                                                  |
| 10.20 |use the logEffectiveWebXml and metadata-complete settings for deploying applications in production (Scored) |          | X |     |                                                                  |
| |Level 2                                                                                                           |          |   |     |                                                                  |
| 1 |Remove Extraneous Resources                                                                                     |          |   |     |                                                                  |
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
