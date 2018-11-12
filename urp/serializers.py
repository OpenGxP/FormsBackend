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
from .models import Status, Permissions, Users, Roles, Settings
from basics.custom import generate_checksum, intersection_two, generate_to_hash


##########
# STATUS #
##########

# read
class StatusReadSerializer(serializers.ModelSerializer):
    valid = serializers.CharField(source='verify_checksum')

    class Meta:
        model = Status
        exclude = ('id', 'checksum', )


###############
# PERMISSIONS #
###############

# read
class PermissionsReadSerializer(serializers.ModelSerializer):
    valid = serializers.CharField(source='verify_checksum')

    class Meta:
        model = Permissions
        exclude = ('id', 'checksum',)


#########
# ROLES #
#########

# read
class RolesReadSerializer(serializers.ModelSerializer):
    valid = serializers.CharField(source='verify_checksum')
    status = StatusReadSerializer()
    permissions = PermissionsReadSerializer(many=True)

    class Meta:
        model = Roles
        exclude = ('id', 'checksum',)


# write
class RolesWriteSerializer(serializers.ModelSerializer):
    valid = serializers.CharField(source='verify_checksum', read_only=True)
    status = StatusReadSerializer(read_only=True)
    # permissions = serializers.PrimaryKeyRelatedField(queryset=Permissions.objects.all(), many=True, required=False)
    permissions = serializers.CharField(required=False)

    # function for create (POST)
    def create(self, validated_data):
        # return Roles.objects.new(**validated_data)
        validated_data['version'] = 1
        validated_data['status_id'] = Settings.objects.status_id(status='draft')
        fields = dict(validated_data)
        fields.pop('permissions')
        role = Roles(**fields)
        ids = {
            'id': role.id,
            'lifecycle_id': role.lifecycle_id
        }
        hash_sequence = Roles.objects.HASH_SEQUENCE
        hash_sequence_mtm = Roles.objects.HASH_SEQUENCE_MTM
        for attr in hash_sequence_mtm:
            if attr in validated_data.keys():
                tmp = list()
                for lifecycle_id in validated_data[attr].split(';'):
                    perm = Permissions.objects.get(lifecycle_id=lifecycle_id)
                    tmp.append(perm)
                fields[attr] = tmp
        to_hash = generate_to_hash(fields=fields, ids=ids, hash_sequence=hash_sequence,
                                   hash_sequence_mtm=hash_sequence_mtm)
        role.checksum = generate_checksum(to_hash)
        role.save()
        role.permissions.set(tmp)
        return role

    # update
    def update(self, instance, validated_data):
        # if getattr(instance, 'verify_checksum')():
        ids = {
            'id': instance.id,
            'lifecycle_id': instance.lifecycle_id
        }
        hash_sequence = Roles.objects.HASH_SEQUENCE
        hash_sequence_mtm = Roles.objects.HASH_SEQUENCE_MTM
        fields = dict()
        for attr in hash_sequence:
            if attr in validated_data.keys():
                fields[attr] = validated_data[attr]
                setattr(instance, attr, validated_data[attr])
            else:
                fields[attr] = getattr(instance, attr)
        for attr in hash_sequence_mtm:
            if attr in validated_data.keys():
                tmp = list()
                for lifecycle_id in validated_data[attr].split(';'):
                    perm = Permissions.objects.get(lifecycle_id=lifecycle_id)
                    tmp.append(perm)
                instance.permissions.set(tmp)
                fields[attr] = tmp
            else:
                a = getattr(instance, attr)
                fields[attr] = getattr(instance, attr)
        to_hash = generate_to_hash(fields=fields, ids=ids, hash_sequence=hash_sequence,
                                   hash_sequence_mtm=hash_sequence_mtm)
        instance.checksum = generate_checksum(to_hash)
        instance.save()
        return instance

    """def validate(self, data): --- function to access all data and validate between"""
    def validate(self, data):
        try:
            if str(self.instance.status.id) != Settings.objects.filter(key='status_draft_id').get().value:
                raise serializers.ValidationError('Updates are only permitted in status "Draft".')
        except AttributeError:
            pass
        return data

    class Meta:
        model = Roles
        exclude = ('id', 'checksum', )
        extra_kwargs = {'version': {'read_only': True}}


#########
# USERS #
#########

# read
class UsersReadSerializer(serializers.ModelSerializer):
    valid = serializers.CharField(source='verify_checksum')
    status = StatusReadSerializer()
    roles = RolesReadSerializer(many=True)

    class Meta:
        model = Users
        exclude = ('id', 'checksum', 'password', 'is_active')
