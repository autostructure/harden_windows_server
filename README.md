# harden_windows_server

## Module Description
This module hardens Windows Server 2008 R2 to the most recent CIS Benchmark, which can be found here:

https://www.cisecurity.org/cis-benchmarks/

## Setup
To use this module, you need to specify whether or not the node is a **Domain Controller** or a **Member Server** by modifying the is_domain_controller parameter. The CIS Benchmark recommends a different security configuration for each type of node. This module defaults to the **Member Server** configuration.

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
>
**Level 1** items intend to:

o be practical and prudent;

o provide a clear security benefit; and

o not inhibit the utility of the technology beyond acceptable means.
>
**Level 2** items exhibit one or more of the following characteristics:

o are intended for environments or use cases where security is paramount

o acts as defense in depth measure

o may negatively inhibit the utility or performance of the technology


By default, all **Level 1** items are managed by the module. However, each organization is unique and might need to disable certain **Level 1** items so that they can configure them themselves. See our reference for a list of all managed items and disable them as shown below, if needed.

For example, the ensure_account_lockout_duration_is_set_to_15_or_more_minutes item sets the lockout duration to 30 minutes by default. If your organization requires a different lockout duration, disable this parameter so you can manually configure it. In a future release, you will be able to manage custom values within the module.

Disable ensure_account_lockout_duration_is_set_to_15_or_more_minutes:

``` puppet
class { 'harden_windows_server':
  is_domain_controller => false,
  ensure_account_lockout_duration_is_set_to_15_or_more_minutes => false,
}
```

## Reference

## Limitations

## Development
Future Release: 

Add more level 2 features
Allow customization

## Contributers
Jack Coleman
