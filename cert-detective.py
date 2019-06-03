import ssl
import socket
import OpenSSL
import yaml
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
from datetime import datetime


def read_app_settings():
    """
    Opens the YAML config file for the application and read the application settings.

    :return: The contents of the YAML config file
    """
    document = open('config.yaml', 'r')
    return yaml.load(document, Loader=yaml.FullLoader)


def get_server_certificate(host, port=443, timeout=10):
    """
    Retrieves the SSL / TLS certificate associated with a given URL and port number.

    :param host: The URL of the website / web service protected by the SSL / TLS cert in question
    :param port: The port number of the website / web service, typically will be 443
    :param timeout: The number of seconds to wait before considering the connection request to have timed out
    :return: a PEM-encoded string version of the SSL / TLS certificate for the URL and port number specified
    """
    context = ssl.create_default_context()
    conn = socket.create_connection((host, port))
    sock = context.wrap_socket(conn, server_hostname=host)
    sock.settimeout(timeout)

    try:
        der_cert = sock.getpeercert(True)
    finally:
        sock.close()

    return ssl.DER_cert_to_PEM_cert(der_cert)


def check_days_remaining(cert):
    """
    Checks the number of days of validity remaining for the given certificate

    :param cert: A certificate is x509 format
    :return: The number of days of validity remaining for the given certificate
    """
    current_date_time = datetime.now()
    cert_expiry_date = datetime.strptime(str(cert.get_notAfter(), 'utf-8'), '%Y%m%d%H%M%SZ')
    return cert_expiry_date - current_date_time


def retrieve_cert_details(cert):
    """
    Gets the basic details of the given certificate, i.e.
    - common name
    - issuer
    - expiry date

    :param cert: A certificate in x509 format
    :return: A dictionary containing the details of the given certificate
    """
    cert_details = dict()
    cert_details['common_name'] = cert.get_subject().commonName
    cert_details['cert_issuer'] = cert.get_issuer().commonName
    cert_details['expiry_date'] = datetime.strptime(str(cert.get_notAfter(), 'utf-8'), '%Y%m%d%H%M%SZ')
    return cert_details


def sendgrid_email_alert(cert_details, recipient, sendgrid_api_key):
    """
    Sends an email to a recipient

    :param cert_details: A dict containing some key details of the certificate that is due to expire soon
    :param recipient: The email address to which the notification should be sent
    :param sendgrid_api_key: An API key generated / retrieved via the SendGrid portal
    :return: The HTTPS status code returned by the mail server
    """
    message = Mail(
        from_email='from_email@example.com',
        to_emails=recipient,
        subject='TLS / SSL cert expires soon (' + cert_details['common_name'] + ')',
        html_content='<strong>Certificate Common Name: </strong>' + cert_details['common_name'] +
        '<p><strong>Issuer: </strong>' + cert_details['cert_issuer'] + '</p>'
        '<p><strong>Expiry Date: </strong>' + cert_details['expiry_date'].strftime("%d-%b-%Y (%H:%M:%S.%f)") + '</p>'
    )

    try:
        sg = SendGridAPIClient(sendgrid_api_key)
        response = sg.send(message)
        return response.status_code

    except Exception as e:
        print(e.message)


# Get the settings for the application from its config file
app_config = read_app_settings()
cert_list = app_config['certs']
days_remaining_threshold = int(app_config['days_remaining_threshold'])
sendgrid_api_key = app_config['sendgrid_api_key']
email_recipient = app_config['notification_contact']

# For each URL in the config file, get its certificate and check its remaining validity period
for cert in cert_list:

    # Get the PEM-encoded cert for the given URL / port number and convert it to x509 format
    certificate = get_server_certificate(cert['url'], port=cert['port'])
    x509_certificate = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, certificate)

    # Send an email with the details of the certificate due to expire soon
    if check_days_remaining(x509_certificate).days <= days_remaining_threshold:
        details = retrieve_cert_details(x509_certificate)
        print(sendgrid_email_alert(details, email_recipient, sendgrid_api_key))


