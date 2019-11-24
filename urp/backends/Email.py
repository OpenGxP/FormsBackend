"""
opengxp.org
Copyright (C) 2019  Henrik Baran

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""


# python imports
import threading
import logging
from smtplib import SMTPException

# django imports
from django.conf import settings
from django.core.mail.backends.smtp import EmailBackend
from django.core.exceptions import ImproperlyConfigured
from django.core.mail.utils import DNS_NAME
from django.core.mail import send_mail

# custom imports
from ..models import Email
from basics.models import Settings
from ..crypto import decrypt

# define logger
logger = logging.getLogger(__name__)


class MyEmailBackend(EmailBackend):
    """
    Send emails against settings.EMAIL_BACKEND.
    """

    def __init__(self, host=None, port=None, username=None, password=None,
                 use_tls=None, fail_silently=False, use_ssl=None, timeout=None,
                 ssl_keyfile=None, ssl_certfile=None, check_call=False,
                 **kwargs):
        super().__init__(fail_silently=fail_silently)
        self.check_call = check_call
        if not self.check_call:
            # check if user configured email hosts
            self.configured_hosts = Email.objects.get_hosts()

            # raise an error that leads to
            if not self.configured_hosts:
                error = 'No email hosts configured.'
                logger.warning(error)
                raise ImproperlyConfigured(error)

        # custom properties
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.use_ssl = use_ssl

        # standard
        self.timeout = settings.EMAIL_SERVER_CONNECTION_TIMEOUT if timeout is None else timeout
        self.use_tls = settings.EMAIL_USE_TLS if use_tls is None else use_tls
        self.ssl_keyfile = settings.EMAIL_SSL_KEYFILE if ssl_keyfile is None else ssl_keyfile
        self.ssl_certfile = settings.EMAIL_SSL_CERTFILE if ssl_certfile is None else ssl_certfile
        if self.use_ssl and self.use_tls:
            raise ValueError(
                "EMAIL_USE_TLS/EMAIL_USE_SSL are mutually exclusive, so only set "
                "one of those settings to True.")
        self.connection = None
        self._lock = threading.RLock()

    def open(self):
        # cache errors
        errors = list()

        if not self.check_call:
            # parse configured hosts and try to connect
            for record in self.configured_hosts:
                self.host = record.host
                self.port = record.port
                self.username = record.username
                self.password = decrypt(record.password)
                self.use_ssl = record.use_ssl

                try:
                    return self._open()
                except OSError as e:
                    logger.warning('Cannot open connection to host: "{}". Details: {}'.format(self.host, e))
                    errors.append(e)
                    continue
        else:
            try:
                return self._open()
            except OSError as e:
                logger.warning('Cannot open connection to host: "{}". Details: {}'.format(self.host, e))
                raise ImproperlyConfigured(e)

        error = 'Cannot connect to any configured hosts. Details: {}'.format(errors)
        logger.error(error)
        raise ImproperlyConfigured(error)

    def _open(self):
        """
        Ensure an open connection to the email server. Return whether or not a
        new connection was required (True or False) or None if an exception
        passed silently.
        """
        if self.connection:
            # Nothing to do if the connection is already open.
            return False

        # If local_hostname is not specified, socket.getfqdn() gets used.
        # For performance, we use the cached FQDN for local_hostname.
        connection_params = {'local_hostname': DNS_NAME.get_fqdn()}
        if self.timeout is not None:
            connection_params['timeout'] = self.timeout
        if self.use_ssl:
            connection_params.update({
                'keyfile': self.ssl_keyfile,
                'certfile': self.ssl_certfile,
            })
        try:
            self.connection = self.connection_class(self.host, self.port, **connection_params)

            # TLS/SSL are mutually exclusive, so only attempt TLS over
            # non-secure connections.
            if not self.use_ssl and self.use_tls:
                self.connection.starttls(keyfile=self.ssl_keyfile, certfile=self.ssl_certfile)
            if self.username and self.password:
                self.connection.login(self.username, self.password)
            return True
        except OSError:
            if not self.fail_silently:
                raise


def send_email(email, html_message, subject):
    recipient_list = []
    if isinstance(email, str):
        recipient_list.append(email)
    if isinstance(email, list):
        recipient_list += email
    try:
        send_mail(subject=subject,
                  message='opengxp message',
                  html_message=html_message,
                  from_email=Settings.objects.email_sender,
                  recipient_list=recipient_list)
    except SMTPException as e:
        logger.error('Email could not be send. Details: {}'.format(e))
    except ImproperlyConfigured:
        pass
