# Qintel PMI

Publisher: Qintel, LLC \
Connector Version: 1.0.1 \
Product Vendor: Qintel, LLC \
Product Name: PMI \
Minimum Product Version: 5.3.0

Qintel’s Patch Management Intelligence (PMI) product simplifies the vulnerability management process by providing vital context around reported Common Vulnerabilities and Exposures. With this app, users can query PMI to surface CVEs that are known by Qintel to be leveraged by adversaries of all stripes

### Configuration variables

This table lists the configuration variables required to operate Qintel PMI. These variables are specified when configuring a PMI asset in Splunk SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**client_id** | required | string | API Token - Client ID |
**client_secret** | required | password | API Token - Client Secret |
**remote** | optional | string | PMI API URL (Optional) |

### Supported Actions

[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity using supplied configuration \
[get cve intel](#action-get-cve-intel) - Fetch CVE intel observations from PMI

## action: 'test connectivity'

Validate the asset configuration for connectivity using supplied configuration

Type: **test** \
Read only: **True**

#### Action Parameters

No parameters are required for this action

#### Action Output

No Output

## action: 'get cve intel'

Fetch CVE intel observations from PMI

Type: **investigate** \
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**cve** | required | CVE to query | string | `cve` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.cve | string | `cve` | |
action_result.summary.observation_count | string | | |
action_result.summary.last_observed | numeric | | |
action_result.status | string | | success failed |
action_result.data.cvss | numeric | | |
action_result.data.affected_system | string | | |
action_result.data.affected_versions | string | | |
action_result.data.\*.observations.\*.observation_date | string | | |
action_result.data.\*.observations.\*.actor_type | string | | |
action_result.data.\*.observations.\*.actor | string | | |
action_result.data.\*.observations.\*.exploit_type | string | | |
action_result.data.\*.observations.\*.notes | string | | |
action_result.message | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

______________________________________________________________________

Auto-generated Splunk SOAR Connector documentation.

Copyright 2025 Splunk Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.
