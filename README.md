# Qintel PMI App for Splunk SOAR

## Description

Qintel’s Patch Management Intelligence (PMI) product simplifies the vulnerability management process by providing vital 
context around reported Common Vulnerabilities and Exposures. With this app, users can query PMI to surface CVEs that 
are known by Qintel to be leveraged by adversaries of all stripes.

For more information, existing customers can visit our
[Integrations Documentation](https://docs.qintel.com/integrations/overview).

## Actions

### get cve intel

Fetch CVE intel observations from PMI. Returns the following elements:

#### CVE Details
- CVE
- CVSS
- Affected System
- Affected Versions
- Last Observation Date

#### Observation Details

- Observation Date
- Actor Type
- Actor
- Exploit Type
- Obsevation Notes


### test connectivity

Test connectivity to the PMI API

## Contact Information

_Sales:_ contactus@qintel.com

_Support:_ integrations-support@qintel.com

## Legal and License

This Phantom App is licensed under the Apache 2.0 license.