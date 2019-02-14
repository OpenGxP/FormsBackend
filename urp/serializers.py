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
from basics.models import AVAILABLE_STATUS
from .decorators import require_STATUS_CHANGE, require_POST, require_DELETE, require_PATCH, require_NONE, \
    require_NEW_VERSION, require_ROLES, require_status
from .custom import UserName

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
        if self.context['function'] == 'new_version':
            # lifecycle_id
            setattr(obj, 'lifecycle_id', self.instance.lifecycle_id)
            # version
            for attr in hash_sequence:
                validated_data[attr] = getattr(self.instance, attr)
            validated_data['version'] = self.instance.version + 1
        else:
            validated_data['version'] = 1
            # for users
            if obj.MODEL_ID == '04':
                validated_data['is_active'] = True
                validated_data['initial_password'] = True
                username = UserName(first_name=validated_data['first_name'],
                                    last_name=validated_data['last_name'],
                                    existing_users=Users.objects.existing_users)
                validated_data['username'] = username.algorithm
        # add default fields for new objects
        if model.objects.HAS_STATUS:
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
            # update instance in case of POST methods with initial instance (e.g. new version)
            self.instance = obj
            return obj

    # update
    def update(self, instance, validated_data, self_call=None):
        if 'function' in self.context.keys():
            if self.context['function'] == 'status_change':
                validated_data['status_id'] = Status.objects.status_by_text(self.context['status'])

                # change "valid_to" of previous version to "valid from" of new version
                # only for set productive step
                if self.context['status'] == 'productive' and self.instance.version > 1 and not self_call:
                    model = getattr(getattr(self, 'Meta', None), 'model', None)
                    prev_instance = model.objects.get_previous_version(instance)
                    data = {'valid_to': self.instance.valid_from}
                    # if no valid_to, always set
                    valid_to_prev_version = getattr(prev_instance, 'valid_to')
                    if not valid_to_prev_version:
                        self.update(instance=prev_instance, validated_data=data, self_call=True)
                    else:
                        # only overlapping validity ranges
                        if getattr(instance, 'valid_from') < valid_to_prev_version:
                            self.update(instance=prev_instance, validated_data=data, self_call=True)

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

    def delete(self):
        # get meta model assigned in custom serializer
        self.instance.delete()

    def validate(self, data):
        if self.context['function'] == 'init':
            return data

        # decorators for status catch
        require_draft = require_status(Status.objects.draft)
        require_circulation = require_status(Status.objects.circulation)
        require_productive = require_status(Status.objects.productive)
        require_blocked = require_status(Status.objects.blocked)
        require_inactive = require_status(Status.objects.inactive)
        require_archived = require_status(Status.objects.archived)

        class Validate:
            def __init__(self, validate_method):
                self.model = getattr(getattr(validate_method, 'Meta', None), 'model', None)
                self.context = validate_method.context
                self.instance = validate_method.instance
                self.function = validate_method.context['function']
                self.method_list = [func for func in dir(self) if callable(getattr(self, func))]
                self.validate()

            def validate(self):
                for method in self.method_list:
                    if method.startswith('validate_'):
                        getattr(self, method)()

        @require_PATCH
        class Patch(Validate):
            @require_STATUS_CHANGE
            def validate_correct_status(self):
                # verify if valid status
                if self.context['status'] not in AVAILABLE_STATUS:
                    raise serializers.ValidationError('Target status not valid. Only "{}" are allowed.'
                                                      .format(AVAILABLE_STATUS))

            @require_STATUS_CHANGE
            @require_draft
            def validate_draft(self):
                if self.context['status'] != 'circulation':
                    raise serializers.ValidationError('Circulation can only be started from status draft.')

                # validation for unique characteristic on start circulation
                validation_unique = self.model.objects.validate_unique(self.instance)
                if validation_unique:
                    raise serializers.ValidationError(validation_unique)

                # validate for "valid from" of new version shall not be before old version
                # only for circulations of version 2 and higher
                if self.instance.version > 1:
                    last_version = self.instance.version - 1
                    query = self.model.objects.filter(lifecycle_id=self.instance.lifecycle_id). \
                        filter(version=last_version).get()
                    if self.instance.valid_from < query.valid_from:
                        raise serializers.ValidationError('Valid from can not be before valid from '
                                                          'of previous version')

            @require_STATUS_CHANGE
            @require_circulation
            def validate_circulation(self):
                if self.context['status'] not in ['productive', 'draft']:
                    raise serializers.ValidationError('From circulation only reject to draft and set '
                                                      'productive are allowed.')

            @require_STATUS_CHANGE
            @require_productive
            def validate_productive(self):
                if self.context['status'] not in ['blocked', 'inactive', 'archived']:
                    raise serializers.ValidationError('From productive only block, archive and inactivate are '
                                                      'allowed.')

            @require_STATUS_CHANGE
            @require_blocked
            def validate_blocked(self):
                if self.context['status'] != 'productive':
                    raise serializers.ValidationError('From blocked only back to productive is allowed')

            @require_STATUS_CHANGE
            @require_inactive
            def validate_inactive(self):
                if self.context['status'] != 'blocked':
                    raise serializers.ValidationError('From inactive only blocked is allowed')

            @require_STATUS_CHANGE
            @require_archived
            def validate_archived(self):
                raise serializers.ValidationError('No status change is allowed from archived.')

            @require_NONE
            def validate_updates_only_in_draft(self):
                if self.instance.status.id != Status.objects.draft:
                    raise serializers.ValidationError('Updates are only permitted in status draft.')

            # model specific rules
            @require_ROLES
            def validate_tbd(self):
                pass

        @require_POST
        class Post(Validate):
            @require_NEW_VERSION
            def validate_only_draft_or_circulation(self):
                if self.instance.status.id == Status.objects.draft or \
                        self.instance.status.id == Status.objects.circulation:
                    raise serializers.ValidationError('New versions can only be created in status productive, '
                                                      'blocked, inactive or archived.')

        @require_DELETE
        class Delete(Validate):
            def validate_delete_only_in_draft(self):
                if self.instance.status.id != Status.objects.draft:
                    raise serializers.ValidationError('Delete is only permitted in status draft.')

        Patch(self)
        Post(self)
        Delete(self)

        return data


##########
# STATUS #
##########

# read
class StatusReadWriteSerializer(GlobalReadWriteSerializer):

    class Meta:
        model = Status
        exclude = ('id', 'checksum', )


###############
# PERMISSIONS #
###############

# read
class PermissionsReadWriteSerializer(GlobalReadWriteSerializer):

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


class RolesDeleteStatusSerializer(GlobalReadWriteSerializer):
    status = serializers.CharField(source='get_status', read_only=True)

    class Meta:
        model = Roles
        exclude = ('id', 'checksum', )
        extra_kwargs = {'version': {'required': False},
                        'role': {'required': False},
                        'valid_from': {'required': False}}


class RolesNewVersionSerializer(GlobalReadWriteSerializer):
    status = serializers.CharField(source='get_status', read_only=True)

    class Meta:
        model = Roles
        exclude = ('id', 'checksum', )
        extra_kwargs = {'version': {'required': False},
                        'role': {'required': False},
                        'valid_from': {'required': False}}


#########
# USERS #
#########

# read
class UsersReadSerializer(GlobalReadWriteSerializer):
    status = serializers.CharField(source='get_status')

    class Meta:
        model = Users
        exclude = ('id', 'checksum', 'password', 'is_active')


# write
class UsersWriteSerializer(GlobalReadWriteSerializer):
    status = serializers.CharField(source='get_status', read_only=True)

    class Meta:
        model = Users
        exclude = ('id', 'checksum', 'is_active')
        extra_kwargs = {'version': {'required': False},
                        'username': {'required': False},
                        'email': {'required': False},
                        'initial_password': {'required': False},
                        'password': {'write_only': True}}


class UsersNewVersionSerializer(GlobalReadWriteSerializer):
    status = serializers.CharField(source='get_status', read_only=True)

    class Meta:
        model = Users
        exclude = ('id', 'checksum', 'is_active', 'password')
        extra_kwargs = {'version': {'required': False},
                        'username': {'required': False},
                        'first_name': {'required': False},
                        'last_name': {'required': False},
                        'initial_password': {'required': False},
                        'roles': {'required': False},
                        'valid_from': {'required': False}}


class UsersDeleteStatusSerializer(GlobalReadWriteSerializer):
    status = serializers.CharField(source='get_status', read_only=True)

    class Meta:
        model = Users
        exclude = ('id', 'checksum', 'is_active', 'password')
        extra_kwargs = {'version': {'required': False},
                        'username': {'required': False},
                        'first_name': {'required': False},
                        'last_name': {'required': False},
                        'initial_password': {'required': False},
                        'roles': {'required': False},
                        'valid_from': {'required': False}}
