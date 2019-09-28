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

# rest imports
from rest_framework import serializers

# app imports
from urp.models.users import Users, UsersLog
from urp.models.roles import Roles
from urp.serializers import GlobalReadWriteSerializer


# read / add / edit
class UsersReadWriteSerializer(GlobalReadWriteSerializer):
    status = serializers.CharField(source='get_status', read_only=True)
    password_verification = serializers.CharField(write_only=True, required=False)

    class Meta:
        model = Users
        extra_kwargs = {'version': {'required': False},
                        'initial_password': {'read_only': True},
                        'password': {'write_only': True,
                                     'required': False}}
        fields = model.objects.GET_MODEL_ORDER + model.objects.GET_BASE_ORDER_STATUS_MANAGED + \
            model.objects.GET_BASE_CALCULATED + ('password_verification',)

    def validate_roles(self, value):
        allowed = Roles.objects.get_by_natural_key_productive_list('role')
        value_list = value.split(',')
        for item in value_list:
            if item not in allowed:
                raise serializers.ValidationError('Not allowed to use "{}".'.format(item))
        return value


# new version / status
class UsersNewVersionStatusSerializer(GlobalReadWriteSerializer):
    status = serializers.CharField(source='get_status', read_only=True)

    class Meta:
        model = Users
        extra_kwargs = {'version': {'required': False},
                        'username': {'required': False},
                        'first_name': {'required': False},
                        'last_name': {'required': False},
                        'email': {'required': False},
                        'initial_password': {'required': False},
                        'roles': {'required': False},
                        'valid_from': {'required': False},
                        'ldap': {'required': False}}
        fields = Users.objects.GET_MODEL_ORDER_NO_PW + Users.objects.GET_BASE_ORDER_STATUS_MANAGED + \
            Users.objects.GET_BASE_CALCULATED


# delete
class UsersDeleteSerializer(GlobalReadWriteSerializer):
    class Meta:
        model = Users
        fields = ()


# read logs
class UsersLogReadSerializer(GlobalReadWriteSerializer):
    status = serializers.CharField(source='get_status')

    class Meta:
        model = UsersLog
        fields = UsersLog.objects.GET_MODEL_ORDER_NO_PW + ('initial_password',) + \
            Users.objects.GET_BASE_ORDER_STATUS_MANAGED + UsersLog.objects.GET_BASE_ORDER_LOG + \
            UsersLog.objects.GET_BASE_CALCULATED
