
VERSION = '1.0.0'
USER_AGENT = 'Splunk-SOAR-'
USER_AGENT += VERSION

DATE_FORMAT = '%Y-%m-%d %I:%M:%S'

CVE_URL = 'https://pmi.qintel.com/overview/cves/{cve}/detail'

# Messages

ERR_TEST_CONN = "Test Connectivity Failed {err}"
ERR_PROCESS_RV = "Error occurred while processing the response from server {err}"  # noqa
