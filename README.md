# wazuh-sca-mailer.py

## About
This script fetches SCA check results from Wazuh API and sends a mail with the results as CSV.
Multiple targets can be configured with different hostname filters, policies and recipients.
Useful as a daily/weekly digest of problematic configs in your environment.

## Usage
```
wazuh-sca-mailer.py [-c CONFIGFILE] [-l LOGFILE] [-s]
```
* -c config file location (default: /etc/wazuh-sca-mailer/wazuh-sca-mailer.conf)
* -l log file location (default: /var/log/wazuh-sca-mailer.log)
* -s silent mode
