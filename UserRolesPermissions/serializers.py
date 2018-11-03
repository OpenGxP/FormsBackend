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
import UserRolesPermissions.models as models
from .models import Status, Permissions, Users, Roles


##########
# STATUS #
##########

# read
class StatusReadSerializer(serializers.ModelSerializer):
    valid = serializers.CharField(source='verify_checksum')

    class Meta:
        model = models.Status
        exclude = ('checksum',)


###############
# PERMISSIONS #
###############

# read
class PermissionsReadSerializer(serializers.ModelSerializer):
    valid = serializers.CharField(source='verify_checksum')

    class Meta:
        model = Permissions
        exclude = ('checksum',)


#########
# ROLES #
#########

# read
class RolesReadSerializer(serializers.ModelSerializer):
    valid = serializers.CharField(source='verify_checksum')
    status = StatusReadSerializer()
    permissions = PermissionsReadSerializer(many=True)

    class Meta:
        model = models.Roles
        exclude = ('checksum',)


# write - sub serializer to establish many to many self reference
class SubRolesWriteSerializer(serializers.ModelSerializer):
    valid = serializers.CharField(source='verify_checksum', read_only=True)
    status = StatusReadSerializer(read_only=True)
    permissions = serializers.PrimaryKeyRelatedField(queryset=Permissions.objects.all(), many=True,
                                                     required=False)

    # function for create (POST)
    def create(self, validated_data):
        return Roles.objects.new(**validated_data)

    """"# update
    def update(self, instance, validated_data):
        instance.status = validated_data.get('status', instance.status)
        instance.save()
        return instance"""

    # def validate(self, data): --- function to access all data and validate between
    # def validate_status(self, value): --- function to implicitly validate field "status"

    class Meta:
        model = Roles
        exclude = ('checksum', )
        extra_kwargs = {'version': {'read_only': True}}


# write
class RolesSerializer(SubRolesWriteSerializer):
    sod_roles = SubRolesWriteSerializer(many=True, required=False)


#########
# USERS #
#########

# read
class UsersReadSerializer(serializers.ModelSerializer):
    valid = serializers.CharField(source='verify_checksum')
    status = StatusReadSerializer()
    roles = RolesReadSerializer(many=True)

    class Meta:
        model = models.Users
        exclude = ('checksum', 'password',)
