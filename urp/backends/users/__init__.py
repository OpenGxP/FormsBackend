"""
opengxp.org
Copyright (C) 2020 Henrik Baran

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

# custom imports
from urp.serializers.logs.access import AccessLogReadWriteSerializer
from urp.serializers.users import UsersDeleteSerializer
from urp.models.settings import Settings
from urp.models.access import AccessLog
from urp.checks import Check

# rest imports
from rest_framework import serializers

# django imports
from django.conf import settings
from django.utils import timezone
from django.contrib.auth.backends import ModelBackend
from django.contrib.auth import get_user_model
from django.utils.translation import ugettext_lazy as _

# variables
USER_MODEL = get_user_model()
ERROR_TEXT_AUTH = _('False username and / or false password and / or user not active.')
ERROR_TEXT_VALID = _('User is not valid.')


def activate_user(user, action_user=None, now=None):
    if not action_user:
        action_user = Settings.objects.core_system_username

    _serializer = UsersDeleteSerializer(user, data={}, context={'method': 'PATCH',
                                                                'function': 'status_change',
                                                                'status': 'productive',
                                                                'user': action_user,
                                                                'now': now})
    if _serializer.is_valid():
        _serializer.save()


def write_access_log(data):
    _serializer = AccessLogReadWriteSerializer(data=data, context={'method': 'POST', 'function': 'new'})
    if _serializer.is_valid():
        _serializer.save()


class BaseModelBackend(ModelBackend):
    def __init__(self):
        # default data
        self.data = {
            'user': None,
            'timestamp': None,
            'mode': 'manual',
            'method': Settings.objects.core_devalue,
            'action': settings.DEFAULT_LOG_ATTEMPT,
            'active': 'no',
            'attempt': None
        }
        self.users = None
        self.now = None

    def user_can_authenticate(self, user):
        is_active = getattr(user, 'is_active', None)
        return is_active or is_active is None

    @staticmethod
    def _block_user(user):
        _serializer = UsersDeleteSerializer(user, data={}, context={'method': 'PATCH',
                                                                    'function': 'status_change',
                                                                    'status': 'blocked',
                                                                    'user': Settings.objects.core_system_username})
        if _serializer.is_valid():
            _serializer.save()

    def _attempt(self, username):
        query = AccessLog.objects.latest_record(username)
        if query:
            if query.active == 'no':
                self.data['attempt'] = 1
                return
            # if one of the three action was the previous record, a successful authentication happen, first attempt
            if query.action in [settings.DEFAULT_LOG_LOGIN, settings.DEFAULT_LOG_PASSWORD,
                                settings.DEFAULT_LOG_SIGNATURE, settings.DEFAULT_LOG_QUESTIONS]:
                self.data['attempt'] = 1
                return
            # if an attempt was a previous action, get attempts and increase by one
            if query.action == settings.DEFAULT_LOG_ATTEMPT:
                self.data['attempt'] = int(query.attempt) + 1
                return
        # if no record found, first attempt
        self.data['attempt'] = 1

    def _set_timestamp(self, request):
        now = getattr(request, settings.ATTR_NOW, None)
        if not now:
            now = timezone.now()
            setattr(request, settings.ATTR_NOW, now)
        self.data['timestamp'] = now

    def _set_username(self, username):
        self.data['user'] = username

    def _public(self, request, username, password, initial_password_check, opt_filter_user):
        check = Check(request=request, username=username, opt_filter_user=opt_filter_user,
                      initial_password_check=initial_password_check, public=True)
        if not check.verify_overall():
            # Run the default password hasher once to reduce the timing
            # difference between an existing and a nonexistent user (#20760).
            USER_MODEL().set_password(password)
            # if no record at all was found, no log record can be written
            if check.error == settings.ERROR_NO_RECORD:
                pass
            # if record was found but not prod or prod, but not valid, log record can be written
            elif check.error == settings.ERROR_NO_RECORD_PROD or check.error == settings.ERROR_NO_RECORD_PROD_VALID:
                self._attempt(username=username)
                write_access_log(self.data)
            raise serializers.ValidationError(ERROR_TEXT_AUTH)
