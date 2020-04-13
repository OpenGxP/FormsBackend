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
from basics.models import Settings
from urp.backends.users import BaseModelBackend, ERROR_TEXT_AUTH, write_access_log

# define logger
logger = logging.getLogger(__name__)


class MyInternalUserModelBackend(BaseModelBackend):
    def user_can_authenticate(self, user):
        is_active = getattr(user, 'is_active', None)
        return is_active or is_active is None

    def authenticate(self, request, self_password_change=False, self_question_change=False, signature=False,
                     username=None, password=None, initial_password_check=True, public=False, **kwargs):

        self._set_timestamp(request=request)
        self._set_username(username)

        if public:
            self._public(request=request, username=username, password=password,
                         initial_password_check=initial_password_check, opt_filter_user={'ldap': False,
                                                                                         'external': False})

        user = getattr(request, settings.ATTR_USER, None)
        self._attempt(username=username)

        # verify password
        if user.check_password(password):
            # create log record
            if self_password_change:
                self.data['action'] = settings.DEFAULT_LOG_PASSWORD
            elif self_question_change:
                self.data['action'] = settings.DEFAULT_LOG_QUESTIONS
            elif signature:
                self.data['action'] = settings.DEFAULT_LOG_SIGNATURE
            else:
                self.data['action'] = settings.DEFAULT_LOG_LOGIN
            self.data['active'] = Settings.objects.core_devalue
            self.data['method'] = 'local'
            write_access_log(self.data)
            return user
        # false password but productive and valid user generates speaking error message
        else:
            # create log record
            self.data['action'] = settings.DEFAULT_LOG_ATTEMPT
            self.data['active'] = 'yes'
            self.data['method'] = 'local'
            if self.data['attempt'] >= Settings.objects.auth_maxloginattempts:
                self._block_user(user)
            write_access_log(self.data)
            raise serializers.ValidationError(ERROR_TEXT_AUTH)
