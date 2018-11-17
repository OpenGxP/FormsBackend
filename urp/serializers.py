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

# django imports
from django.db import IntegrityError


##########
# GLOBAL #
##########

class GlobalReadWriteSerializer(serializers.ModelSerializer):
    valid = serializers.BooleanField(source='verify_checksum', read_only=True)

    @staticmethod
    def new_version_check(data):
        if 'lifecycle_id' in data and 'version' in data:
            return True
        return

    # function for create (POST)
    def create(self, validated_data):
        # get meta model assigned in custom serializer
        model = getattr(getattr(self, 'Meta', None), 'model', None)
        obj = model()
        hash_sequence = obj.HASH_SEQUENCE
        # check if new version or initial create
        if self.new_version_check(validated_data):
            lifecycle_id = validated_data['lifecycle_id']
            version = validated_data['version']
            old_obj = model.objects.get(lifecycle_id=lifecycle_id, version=version)
            setattr(obj, 'lifecycle_id', lifecycle_id)
            for attr in hash_sequence:
                validated_data[attr] = getattr(old_obj, attr)
            validated_data['version'] = version + 1
        else:
            validated_data['version'] = 1
        # add default fields for new objects
        validated_data['status_id'] = Status.objects.draft
        # passed keys
        keys = validated_data.keys()
        # set attributes of validated data
        for attr in hash_sequence:
            if attr in keys:
                setattr(obj, attr, validated_data[attr])
        # generate hash
        to_hash = generate_to_hash(fields=validated_data, hash_sequence=hash_sequence, unique_id=obj.id,
                                   lifecycle_id=obj.lifecycle_id)
        obj.checksum = generate_checksum(to_hash)
        # save obj
        try:
            obj.save()
        except IntegrityError as e:
            if 'UNIQUE constraint' in e.args[0]:
                raise serializers.ValidationError('Object already exists.')
        else:
            return obj

    # update
    def update(self, instance, validated_data):
        hash_sequence = instance.HASH_SEQUENCE
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

    def validate(self, data):
        # verify if POST or PUT
        try:
            if self.instance.status.id != Status.objects.draft:
                raise serializers.ValidationError('Updates are only permitted in status draft.')
        except AttributeError:
            if self.new_version_check(data):
                model = getattr(getattr(self, 'Meta', None), 'model', None)
                try:
                    old_obj = model.objects.get(lifecycle_id=data['lifecycle_id'], version=data['version'])
                except model.DoesNotExist:
                    raise serializers.ValidationError('Cannot create new version of non-existing object.')
                else:
                    if old_obj.status.id == Status.objects.draft or old_obj.status.id == Status.objects.circulation:
                        raise serializers.ValidationError('New versions can only be created in status productive, '
                                                          'blocked, inactive or archived.')
        return data


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

    class Meta:
        model = Roles
        exclude = ('id', 'checksum', )
        extra_kwargs = {'version': {'required': False}}


#########
# USERS #
#########

# read
class UsersReadSerializer(GlobalReadWriteSerializer):
    status = serializers.CharField(source='get_status')

    class Meta:
        model = Users
        exclude = ('id', 'checksum', 'password', 'is_active')
