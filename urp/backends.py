"""
opengxp.org
Copyright (C) 2018  Henrik Baran

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

# rest imports
from rest_framework import serializers

# django imports
from django.utils import timezone
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend
from django.utils.translation import ugettext_lazy as _
from django.core.mail.backends.smtp import EmailBackend

# custom imports
from .models import AccessLog, LDAP
from .serializers import AccessLogReadWriteSerializer, UsersDeleteStatusSerializer
from basics.models import Settings


UserModel = get_user_model()
ERROR_TEXT_AUTH = _('False username and / or false password and / or user not active.')
ERROR_TEXT_VALID = _('User is not valid.')


def write_access_log(data):
    _serializer = AccessLogReadWriteSerializer(data=data, context={'method': 'POST', 'function': 'new'})
    if _serializer.is_valid():
        _serializer.save()


def block_user(user):
    _serializer = UsersDeleteStatusSerializer(user, data={}, context={'method': 'PATCH',
                                                                      'function': 'status_change',
                                                                      'status': 'blocked',
                                                                      'user': Settings.objects.core_system_username})
    if _serializer.is_valid():
        _serializer.save()


def attempt(username):
    query = AccessLog.objects.latest_record(username)
    if query:
        if query.action == settings.DEFAULT_LOG_LOGIN:
            return 1, query
        if query.action == settings.DEFAULT_LOG_ATTEMPT:
            return int(query.attempt) + 1, query
    return 1, None


class MyModelBackend(ModelBackend):
    """
    Authenticates against settings.AUTH_USER_MODEL.
    """

    def user_can_authenticate(self, user):
        is_active = getattr(user, 'is_active', None)
        return is_active or is_active is None

    def authenticate(self, request, self_password_change=False, username=None, password=None, **kwargs):
        data = {
            'user': username,
            'timestamp': timezone.now(),
            'mode': 'manual',
            'method': Settings.objects.core_devalue
        }

        if username is None:
            username = kwargs.get(UserModel.USERNAME_FIELD)
        # try to find user(s) in status productive
        try:
            # get effective user
            users = UserModel.objects.get_by_natural_key_productive(username)
        # no user(s) in status productive found
        except UserModel.DoesNotExist:
            # Run the default password hasher once to reduce the timing
            # difference between an existing and a nonexistent user (#20760).
            UserModel().set_password(password)
            # but user(s) in status other than productive exists
            if UserModel.objects.exist(username):
                # create log record
                data['action'] = settings.DEFAULT_LOG_ATTEMPT
                data['active'] = 'no'
                data['attempt'] = attempt(username)[0]
                write_access_log(data)
            raise serializers.ValidationError(ERROR_TEXT_AUTH)
        # user(s) in status productive exist
        else:
            # parse over each existing user in status productive
            for user in users:
                # if user is valid (can only be one off all users in status productive)
                # FO-123: added role valid check as additional criteria for password checks
                if user.verify_validity_range and user.verify_valid_roles and user.verify_sod:
                    # check if ldap user
                    if not user.ldap:
                        # verify password
                        if user.check_password(password):
                            _attempt, query = attempt(username)
                            if query:
                                if query.active == 'no':
                                    data['attempt'] = 1
                                else:
                                    data['attempt'] = _attempt
                            else:
                                data['attempt'] = _attempt
                            # create log record
                            data['action'] = settings.DEFAULT_LOG_LOGIN
                            data['active'] = Settings.objects.core_devalue
                            data['method'] = 'local'
                            if not self_password_change:
                                write_access_log(data)
                            return user
                        # false password but productive and valid user generates speaking error message
                        else:
                            _attempt, query = attempt(username)
                            if query:
                                if query.active == 'no':
                                    data['attempt'] = 1
                                else:
                                    data['attempt'] = _attempt
                            else:
                                data['attempt'] = _attempt
                            # create log record
                            data['action'] = settings.DEFAULT_LOG_ATTEMPT
                            data['active'] = 'yes'
                            data['method'] = 'local'
                            if data['attempt'] >= Settings.objects.auth_maxloginattempts:
                                block_user(user)
                            write_access_log(data)
                    else:
                        # check user password against ldap (bind)
                        if LDAP.objects.bind(username=username, password=password):
                            _attempt, query = attempt(username)
                            if query:
                                if query.active == 'no':
                                    data['attempt'] = 1
                                else:
                                    data['attempt'] = _attempt
                            else:
                                data['attempt'] = _attempt
                            # create log record
                            data['action'] = settings.DEFAULT_LOG_LOGIN
                            data['active'] = Settings.objects.core_devalue
                            data['method'] = 'ldap'
                            write_access_log(data)
                            return user
                        else:
                            _attempt, query = attempt(username)
                            if query:
                                if query.active == 'no':
                                    data['attempt'] = 1
                                else:
                                    data['attempt'] = _attempt
                            else:
                                data['attempt'] = _attempt
                            # create log record
                            data['action'] = settings.DEFAULT_LOG_ATTEMPT
                            data['active'] = 'yes'
                            # FO-139: changed method to ldap
                            data['method'] = 'ldap'
                            if data['attempt'] >= Settings.objects.auth_maxloginattempts:
                                block_user(user)
                            write_access_log(data)
                    raise serializers.ValidationError(ERROR_TEXT_AUTH)

            # no user was valid
            # create log record
            data['action'] = settings.DEFAULT_LOG_ATTEMPT
            data['active'] = 'no'
            data['attempt'] = attempt(username)[0]
            write_access_log(data)
            # Run the default password hasher once to reduce the timing
            # difference between an existing and a nonexistent user (#20760).
            UserModel().set_password(password)
            # FO-123: adapted error message to more general one
            raise serializers.ValidationError(ERROR_TEXT_AUTH)


class MyEmailBackend(EmailBackend):
    """
    Send emails against settings.EMAIL_BACKEND.
    """

    def __init__(self, host=None, port=None, username=None, password=None,
                 use_tls=None, fail_silently=False, use_ssl=None, timeout=None,
                 ssl_keyfile=None, ssl_certfile=None,
                 **kwargs):
        super().__init__(fail_silently=fail_silently)
        self.host = host or settings.EMAIL_HOST
        self.port = port or settings.EMAIL_PORT
        self.username = settings.EMAIL_HOST_USER if username is None else username
        self.password = settings.EMAIL_HOST_PASSWORD if password is None else password
        self.use_tls = settings.EMAIL_USE_TLS if use_tls is None else use_tls
        self.use_ssl = settings.EMAIL_USE_SSL if use_ssl is None else use_ssl
        self.timeout = settings.EMAIL_TIMEOUT if timeout is None else timeout
        self.ssl_keyfile = settings.EMAIL_SSL_KEYFILE if ssl_keyfile is None else ssl_keyfile
        self.ssl_certfile = settings.EMAIL_SSL_CERTFILE if ssl_certfile is None else ssl_certfile
        if self.use_ssl and self.use_tls:
            raise ValueError(
                "EMAIL_USE_TLS/EMAIL_USE_SSL are mutually exclusive, so only set "
                "one of those settings to True.")
        self.connection = None
        self._lock = threading.RLock()
