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

# custom imports
from .models import Status, Permissions, Users, Roles


class StatusSerializer(serializers.HyperlinkedModelSerializer):
    valid = serializers.CharField(source='verify_checksum', read_only=True)

    class Meta:
        model = Status
        fields = ('url', 'status', 'valid')


class PermissionsSerializer(serializers.HyperlinkedModelSerializer):
    valid = serializers.CharField(source='verify_checksum', read_only=True)

    class Meta:
        model = Permissions
        fields = ('url', 'permission', 'valid')


class UsersSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = Users
        fields = ('url', 'username', 'email', 'first_name', 'last_name', 'is_active',
                  'initial_password', 'status', 'version')


class RolesSerializer(serializers.HyperlinkedModelSerializer):
    valid = serializers.CharField(source='verify_checksum', read_only=True)

    class Meta:
        model = Roles
        fields = ('url', 'role', 'permissions', 'status', 'version', 'valid')
