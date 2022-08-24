[comment]: # "Auto-generated SOAR connector documentation"
# Qintel PMI

Publisher: Qintel, LLC  
Connector Version: 1\.0\.1  
Product Vendor: Qintel, LLC  
Product Name: PMI  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 5\.3\.0  

Qintel’s Patch Management Intelligence \(PMI\) product simplifies the vulnerability management process by providing vital context around reported Common Vulnerabilities and Exposures\. With this app, users can query PMI to surface CVEs that are known by Qintel to be leveraged by adversaries of all stripes

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

### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a PMI asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**client\_id** |  required  | string | API Token \- Client ID
**client\_secret** |  required  | password | API Token \- Client Secret
**remote** |  optional  | string | PMI API URL \(Optional\)

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity using supplied configuration  
[get cve intel](#action-get-cve-intel) - Fetch CVE intel observations from PMI  

## action: 'test connectivity'
Validate the asset configuration for connectivity using supplied configuration

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'get cve intel'
Fetch CVE intel observations from PMI

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**cve** |  required  | CVE to query | string |  `cve` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.cve | string |  `cve` 
action\_result\.summary\.observation\_count | string | 
action\_result\.summary\.last\_observed | numeric | 
action\_result\.status | string | 
action\_result\.data\.cvss | numeric | 
action\_result\.data\.affected\_system | string | 
action\_result\.data\.affected\_versions | string | 
action\_result\.data\.\*\.observations\.\*\.observation\_date | string | 
action\_result\.data\.\*\.observations\.\*\.actor\_type | string | 
action\_result\.data\.\*\.observations\.\*\.actor | string | 
action\_result\.data\.\*\.observations\.\*\.exploit\_type | string | 
action\_result\.data\.\*\.observations\.\*\.notes | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 