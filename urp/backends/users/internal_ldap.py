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
from basics.models import Settings
from urp.backends.users import BaseModelBackend, write_access_log, ERROR_TEXT_AUTH, USER_MODEL

# define logger
logger = logging.getLogger(__name__)


class MyInternalLDAPUserModelBackend(BaseModelBackend):
    def user_can_authenticate(self, user):
        is_active = getattr(user, 'is_active', None)
        return is_active or is_active is None

    def authenticate(self, request, self_password_change=False, self_question_change=False, signature=False,
                     username=None, password=None, initial_password_check=True, public=False, **kwargs):

        if not LDAP.objects.exists():
            return None

        # if user exists in as internal managed user no using ldap login, skip this backend
        if USER_MODEL.objects.filter(external=False, ldap=False, username=username).exists():
            return None

        self._set_timestamp(request=request)
        self._set_username(username)

        if public:
            self._public(request=request, username=username, password=password,
                         initial_password_check=initial_password_check, opt_filter_user={'ldap': True,
                                                                                         'external': False})

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
            self.data['method'] = 'ldap_internal'
            write_access_log(self.data)
            return user
        # false password but productive and valid user generates speaking error message
        else:
            # create log record
            self.data['action'] = settings.DEFAULT_LOG_ATTEMPT
            self.data['active'] = 'yes'
            # FO-139: changed method to ldap
            self.data['method'] = 'ldap_internal'
            if self.data['attempt'] >= Settings.objects.auth_maxloginattempts:
                self._block_user(user)
            write_access_log(self.data)
            raise serializers.ValidationError(ERROR_TEXT_AUTH)
