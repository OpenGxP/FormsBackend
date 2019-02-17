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


# rest imports
from rest_framework import serializers

# django imports
from django.utils import timezone
from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend
from django.utils.translation import ugettext_lazy as _

# custom imports
from .models import AccessLog
from .serializers import AccessLogReadWriteSerializer


UserModel = get_user_model()
ERROR_TEXT_AUTH = _('False username and / or false password and / or user not active.')
ERROR_TEXT_VALID = _('User is not valid.')


def write_access_log(data):
    _serializer = AccessLogReadWriteSerializer(data=data, context={'method': 'POST', 'function': 'new'})
    if _serializer.is_valid():
        _serializer.save()


def attempt(username):
    query = AccessLog.objects.latest_record(username)
    if query:
        if query.action == 'login':
            return 1
        if query.action == 'attempt':
            return query.attempt + 1
    else:
        return 1


class MyModelBackend(ModelBackend):
    """
    Authenticates against settings.AUTH_USER_MODEL.
    """

    def user_can_authenticate(self, user):
        is_active = getattr(user, 'is_active', None)
        return is_active or is_active is None

    def authenticate(self, request, username=None, password=None, **kwargs):
        data = {
            'username': username,
            'timestamp': timezone.now(),
            'mode': 'manual',
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
                data['action'] = 'attempt'
                data['active'] = 'no'
                data['attempt'] = attempt(username)
                write_access_log(data)
            raise serializers.ValidationError(ERROR_TEXT_AUTH)
        # user(s) in status productive exist
        else:
            # parse over each existing user in status productive
            for user in users:
                # if user is valid (can only be one off all users in status productive)
                if user.verify_validity_range:
                    # verify password
                    if user.check_password(password):
                        # create log record
                        data['action'] = 'login'
                        data['active'] = '--'
                        data['attempt'] = attempt(username)
                        write_access_log(data)
                        return user
                    # false password but productive and valid user generates speaking error message
                    else:
                        # create log record
                        data['action'] = 'attempt'
                        data['active'] = 'yes'
                        data['attempt'] = attempt(username)
                        write_access_log(data)
                    raise serializers.ValidationError(ERROR_TEXT_AUTH)

            # no user was valid
            # create log record
            data['action'] = 'attempt'
            data['active'] = 'no'
            data['attempt'] = attempt(username)
            write_access_log(data)
            # Run the default password hasher once to reduce the timing
            # difference between an existing and a nonexistent user (#20760).
            UserModel().set_password(password)
            raise serializers.ValidationError(ERROR_TEXT_VALID)
