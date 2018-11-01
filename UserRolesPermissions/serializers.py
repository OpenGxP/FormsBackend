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


class StatusSerializer(serializers.ModelSerializer):
    valid = serializers.CharField(source='verify_checksum', read_only=True)

    # def validate(self, data): --- function to access all data and validate between
    # def validate_status(self, value): --- function to implicitly validate field "status"

    class Meta:
        model = Status
        exclude = ('checksum',)

    # function for create (POST)
    # def create(self, validated_data): --- overwrite always
        # return Status.objects.create(status=validated_data['status')


class PermissionsSerializer(serializers.ModelSerializer):
    valid = serializers.CharField(source='verify_checksum', read_only=True)

    class Meta:
        model = Permissions
        exclude = ('checksum',)


class RolesSerializer(serializers.ModelSerializer):
    valid = serializers.CharField(source='verify_checksum', read_only=True)
    status = StatusSerializer()
    permissions = PermissionsSerializer(many=True)

    class Meta:
        model = Roles
        exclude = ('checksum', )
        # fields = ('url', 'role', 'permissions', 'status', 'version', 'valid')


class UsersSerializer(serializers.ModelSerializer):
    valid = serializers.CharField(source='verify_checksum', read_only=True)
    status = StatusSerializer()
    roles = RolesSerializer(many=True)

    class Meta:
        model = Users
        exclude = ('checksum',)
        extra_kwargs = {'password': {'write_only': True}}
