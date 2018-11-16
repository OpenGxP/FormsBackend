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
from basics.custom import generate_checksum, generate_to_hash


##########
# GLOBAL #
##########

class GlobalReadWriteSerializer(serializers.ModelSerializer):
    valid = serializers.BooleanField(source='verify_checksum', read_only=True)


##########
# STATUS #
##########

# read
class StatusReadSerializer(GlobalReadWriteSerializer):

    class Meta:
        model = Status
        exclude = ('id', 'checksum', )


###############
# PERMISSIONS #
###############

# read
class PermissionsReadSerializer(GlobalReadWriteSerializer):

    class Meta:
        model = Permissions
        exclude = ('id', 'checksum',)


#########
# ROLES #
#########

# read
class RolesReadSerializer(GlobalReadWriteSerializer):
    status = serializers.CharField(source='get_status')

    class Meta:
        model = Roles
        exclude = ('id', 'checksum',)


# write
class RolesWriteSerializer(GlobalReadWriteSerializer):
    status = serializers.CharField(source='get_status', read_only=True)

    # function for create (POST)
    def create(self, validated_data):
        # create role
        model = Roles
        obj = Roles()
        # add default fields for new objects
        validated_data['version'] = 1
        validated_data['status_id'] = Status.objects.draft
        # passed keys
        keys = validated_data.keys()
        # set attributes of validated data
        hash_sequence = model.objects.HASH_SEQUENCE
        for attr in hash_sequence:
            if attr in keys:
                setattr(obj, attr, validated_data[attr])
        # generate hash
        to_hash = generate_to_hash(fields=validated_data, hash_sequence=hash_sequence, unique_id=obj.id,
                                   lifecycle_id=obj.lifecycle_id)
        obj.checksum = generate_checksum(to_hash)
        # save obj
        obj.save()
        return obj

    # update
    def update(self, instance, validated_data):
        hash_sequence = Roles.objects.HASH_SEQUENCE
        fields = dict()
        for attr in hash_sequence:
            if attr in validated_data.keys():
                fields[attr] = validated_data[attr]
                setattr(instance, attr, validated_data[attr])
            else:
                fields[attr] = getattr(instance, attr)
        to_hash = generate_to_hash(fields=fields, hash_sequence=hash_sequence, unique_id=instance.id,
                                   lifecycle_id=instance.lifecycle_id)
        instance.checksum = generate_checksum(to_hash)
        instance.save()
        return instance

    """def validate(self, data): --- function to access all data and validate between"""
    def validate(self, data):
        if self.instance.status.id != Status.objects.draft:
            raise serializers.ValidationError('Updates are only permitted in status "draft".')
        return data

    class Meta:
        model = Roles
        exclude = ('id', 'checksum', )
        extra_kwargs = {'version': {'read_only': True}}


#########
# USERS #
#########

# read
class UsersReadSerializer(GlobalReadWriteSerializer):
    status = serializers.CharField(source='get_status')

    class Meta:
        model = Users
        exclude = ('id', 'checksum', 'password', 'is_active')
