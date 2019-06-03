# cert-detective
A python program to check the SSL / TLS cert for a list of sites, and warn of any that are due to expire soon.

The application reads its config / settings from a YAML file in the below format:

````
# Configuration for the ssl-inspector application
#
# All URLs and port numbers to be checked must be listed below, using the exact format:
#
#  - url: 'www.example.com'
#    port: '443'
#
# Note the hyphen before each url, and that each value is enclosed in apostrophes
certs:
  - url: 'www.example.com'
    port: '443'
  - url: 'www.secondexample.ie'
    port: '8443'
#
# Specify the threshold of days remaining, in order to raise an alert
days_remaining_threshold: '50'
#
# Specify Sendgrid credentials for sending email notifications
sendgrid_api_key: 'key_goes_here'
notification_contact: 'postmaster@example.com'
````