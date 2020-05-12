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

# python imports
import logging

# rest imports
from rest_framework import serializers

# django imports
from django.conf import settings

# custom imports
from urp.models.ldap import LDAP
from urp.checks import Check
from basics.models import Settings
from urp.backends.users import BaseModelBackend, write_access_log, ERROR_TEXT_AUTH, USER_MODEL

# define logger
logger = logging.getLogger(__name__)


class MyExternalLDAPUserModelBackend(BaseModelBackend):
    def user_can_authenticate(self, user):
        return True

    def authenticate(self, request, self_password_change=False, self_question_change=False, signature=False,
                     username=None, password=None, initial_password_check=False, public=False, ext=True, **kwargs):

        # if no ldap server exists, skip this backend
        if not LDAP.objects.exists():
            return None

        # if user exists in as internal managed user, skip this backend
        if USER_MODEL.objects.filter(external=False, username=username).exists():
            return None

        # if user not exists in external system, raise error
        if not LDAP.objects.base_search_user(username):
            raise serializers.ValidationError(ERROR_TEXT_AUTH)

        self._set_timestamp(request=request)
        self._set_username(username)

        if public:
            # initiate check object
            check = Check(request=request, username=username, opt_filter_user={'external': True}, public=True, ext=ext,
                          initial_password_check=False)
            if not check.verify_overall():
                # Run the default password hasher once to reduce the timing
                # difference between an existing and a nonexistent user (#20760).
                USER_MODEL().set_password(password)
                # always create log record, because user is created 100%
                self._attempt(username=username)
                write_access_log(self.data)
                raise serializers.ValidationError(ERROR_TEXT_AUTH)

        # FO-273: use user instance from check, that is the prod valid on every request
        user = getattr(request, 'user', None)
        self._attempt(username=username)

        # check user password against ldap (bind)
        if LDAP.objects.bind(username=username, password=password):
            # create log record
            if signature:
                self.data['action'] = settings.DEFAULT_LOG_SIGNATURE
            else:
                self.data['action'] = settings.DEFAULT_LOG_LOGIN
            self.data['active'] = Settings.objects.core_devalue
            self.data['method'] = 'ldap_external'
            write_access_log(self.data)
            return user
        else:
            # create log record
            self.data['action'] = settings.DEFAULT_LOG_ATTEMPT
            self.data['active'] = 'yes'
            # FO-139: changed method to ldap
            self.data['method'] = 'ldap_external'
            if self.data['attempt'] >= Settings.objects.auth_maxloginattempts:
                self._block_user(user)
            write_access_log(self.data)
            raise serializers.ValidationError(ERROR_TEXT_AUTH)
