# File: qintelpmi_consts.py
#
# Copyright (c) 2009-2022 Qintel, LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.
#

VERSION = '1.0.0'
USER_AGENT = 'Splunk-SOAR-'
USER_AGENT += VERSION

DATE_FORMAT = '%Y-%m-%d %I:%M:%S'

CVE_URL = 'https://pmi.qintel.com/overview/cves/{cve}/detail'

# Messages

ERR_TEST_CONN = "Test Connectivity Failed {err}"
ERR_PROCESS_RV = "Error occurred while processing the response from server {err}"  # noqa
