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
from .models import Status, Permissions, Users, Roles, AccessLog, PermissionsLog, RolesLog, UsersLog, LDAP, LDAPLog
from basics.custom import generate_checksum, generate_to_hash, encrypt
from basics.models import AVAILABLE_STATUS, StatusLog, CentralLog, Settings, SettingsLog
from .decorators import require_STATUS_CHANGE, require_POST, require_DELETE, require_PATCH, require_NONE, \
    require_NEW_VERSION, require_status, require_LDAP, require_USERS, require_NEW
from .custom import create_log_record, create_central_log_record
from .ldap import server_check

# django imports
from django.utils import timezone
from django.db import IntegrityError
from django.conf import settings


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
                # only set initial password for non-ldap managed users
                if not validated_data['ldap']:
                    validated_data['initial_password'] = True
                else:
                    validated_data['initial_password'] = False
            # for access log
            if obj.MODEL_ID == '05':
                create_central_log_record(log_id=obj.id, now=validated_data['timestamp'], context=model.MODEL_CONTEXT,
                                          action=validated_data['action'], user=validated_data['user'])
            # ldap encrypt password before save to db
            if obj.MODEL_ID == '11':
                raw_pw = validated_data['password']
                validated_data['password'] = encrypt(raw_pw)

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
            # log record
            if model.objects.LOG_TABLE:
                create_log_record(model=model, context=self.context, obj=obj, validated_data=validated_data,
                                  action=settings.DEFAULT_LOG_CREATE)
        except IntegrityError as e:
            if 'UNIQUE constraint' in e.args[0]:
                raise serializers.ValidationError('Object already exists.')
        else:
            # update instance in case of POST methods with initial instance (e.g. new version)
            self.instance = obj
            return obj

    # update
    def update(self, instance, validated_data, self_call=None, now=None):
        action = settings.DEFAULT_LOG_UPDATE
        model = getattr(getattr(self, 'Meta', None), 'model', None)
        if 'function' in self.context.keys():
            if self.context['function'] == 'status_change':
                action = settings.DEFAULT_LOG_STATUS
                validated_data['status_id'] = Status.objects.status_by_text(self.context['status'])

                # if "valid_from" is empty, set "valid_from" to timestamp of set productive
                if self.context['status'] == 'productive' and not self.instance.valid_from and not self_call:
                    now = timezone.now()
                    validated_data['valid_from'] = now

                # change "valid_to" of previous version to "valid from" of new version
                # only for set productive step
                if self.context['status'] == 'productive' and self.instance.version > 1 and not self_call:
                    now = timezone.now()
                    prev_instance = model.objects.get_previous_version(instance)
                    data = {'valid_to': self.instance.valid_from}
                    # if no valid_to, always set
                    valid_to_prev_version = getattr(prev_instance, 'valid_to')
                    if not valid_to_prev_version:
                        self.update(instance=prev_instance, validated_data=data, self_call=True, now=now)
                    else:
                        # only overlapping validity ranges
                        if getattr(instance, 'valid_from') < valid_to_prev_version:
                            self.update(instance=prev_instance, validated_data=data, self_call=True, now=now)

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
        # log record
        if model.objects.LOG_TABLE:
            create_log_record(model=model, context=self.context, obj=instance, validated_data=fields,
                              action=action, now=now)
        return instance

    def delete(self):
        # get meta model assigned in custom serializer
        model = getattr(getattr(self, 'Meta', None), 'model', None)
        hash_sequence = model.HASH_SEQUENCE
        fields = dict()
        for attr in hash_sequence:
            fields[attr] = getattr(self.instance, attr)
        self.instance.delete()
        if model.objects.LOG_TABLE:
            create_log_record(model=model, context=self.context, obj=self.instance, validated_data=fields,
                              action=settings.DEFAULT_LOG_DELETE)

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

                # FO-122: SoD check only for set productive
                if self.context['status'] == 'productive':
                    # SoD
                    if 'disable-sod' not in self.context.keys():
                        log = self.model.objects.LOG_TABLE
                        previous_user = log.objects.get_circulation_user_for_sod(self.instance)
                        if previous_user == self.context['user']:
                            raise serializers.ValidationError('SoD conflict - set productive can not be performed by '
                                                              'the same user as set in circulation.')

            @require_STATUS_CHANGE
            @require_USERS
            def validate_users(self):
                # check if used roles are productive
                if self.context['status'] in ['circulation', 'productive']:
                    query = Users.objects.filter(lifecycle_id=self.instance.lifecycle_id,
                                                 version=self.instance.version).get()
                    raw_roles = query.roles.split(',')
                    for role in raw_roles:
                        try:
                            Roles.objects.get_by_natural_key_productive(role)
                        except Roles.DoesNotExist:
                            raise serializers.ValidationError('Role "{}" not in status productive.'.format(role))

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
                if self.model.objects.HAS_STATUS:
                    if self.instance.status.id != Status.objects.draft:
                        raise serializers.ValidationError('Updates are only permitted in status draft.')

            @require_NONE
            @require_LDAP
            def validate_server_check(self):
                server_check(data)

            @require_NONE
            @require_USERS
            def validate_ldap(self):
                if data['ldap']:
                    # in case a password was passed, set to none
                    data['password'] = ''
                    LDAP.objects.search(data)

        @require_POST
        class Post(Validate):
            @require_NEW_VERSION
            def validate_only_draft_or_circulation(self):
                if self.instance.status.id == Status.objects.draft or \
                        self.instance.status.id == Status.objects.circulation:
                    raise serializers.ValidationError('New versions can only be created in status productive, '
                                                      'blocked, inactive or archived.')

            @require_NEW
            @require_LDAP
            def validate_server_check(self):
                server_check(data)

            @require_NEW
            @require_USERS
            def validate_ldap(self):
                if data['ldap']:
                    # in case a password was passed, set to none
                    data['password'] = ''
                    LDAP.objects.search(data)
                else:
                    if 'password' not in data:
                        raise serializers.ValidationError({'password': ['This filed is required.']})

        @require_DELETE
        class Delete(Validate):
            def validate_delete_only_in_draft(self):
                if self.model.objects.HAS_STATUS:
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


# read
class StatusLogReadSerializer(GlobalReadWriteSerializer):
    class Meta:
        model = StatusLog
        exclude = ('id', 'checksum', )


###############
# PERMISSIONS #
###############

# read
class PermissionsReadWriteSerializer(GlobalReadWriteSerializer):
    class Meta:
        model = Permissions
        exclude = ('id', 'checksum',)


# read
class PermissionsLogReadSerializer(GlobalReadWriteSerializer):
    class Meta:
        model = PermissionsLog
        exclude = ('id', 'checksum', )


########
# LDAP #
########

# read
class LDAPReadWriteSerializer(GlobalReadWriteSerializer):
    class Meta:
        model = LDAP
        exclude = ('id', 'checksum',)
        extra_kwargs = {'password': {'write_only': True}}


# read
class LDAPLogReadSerializer(GlobalReadWriteSerializer):
    class Meta:
        model = LDAPLog
        exclude = ('id', 'checksum', )


# delete
class LDAPDeleteSerializer(GlobalReadWriteSerializer):
    class Meta:
        model = LDAP
        fields = ()


############
# SETTINGS #
############

# read/edit
class SettingsReadWriteSerializer(GlobalReadWriteSerializer):
    class Meta:
        model = Settings
        exclude = ('id', 'checksum',)
        extra_kwargs = {'default': {'read_only': True},
                        'key': {'read_only': True}}


# initial write
class SettingsInitialWriteSerializer(GlobalReadWriteSerializer):
    class Meta:
        model = Settings
        exclude = ('id', 'checksum',)


# read
class SettingsLogReadSerializer(GlobalReadWriteSerializer):
    class Meta:
        model = SettingsLog
        exclude = ('id', 'checksum', )


##############
# CENTRALLOG #
##############

# read
class CentralLogReadWriteSerializer(GlobalReadWriteSerializer):
    class Meta:
        model = CentralLog
        exclude = ('id', 'checksum',)


#############
# ACCESSLOG #
#############

# read
class AccessLogReadWriteSerializer(GlobalReadWriteSerializer):
    class Meta:
        model = AccessLog
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


# log
class RolesLogReadSerializer(GlobalReadWriteSerializer):
    status = serializers.CharField(source='get_status')

    class Meta:
        model = RolesLog
        exclude = ('id', 'checksum', )


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
                        'initial_password': {'read_only': True},
                        'password': {'write_only': True,
                                     'required': False}}


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
                        'valid_from': {'required': False},
                        'ldap': {'required': False}}


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
                        'valid_from': {'required': False},
                        'ldap': {'required': False}}


# log
class UsersLogReadSerializer(GlobalReadWriteSerializer):
    status = serializers.CharField(source='get_status')

    class Meta:
        model = UsersLog
        exclude = ('id', 'checksum', 'is_active')


AUDIT_TRAIL_SERIALIZERS = {
    Users.MODEL_CONTEXT.lower(): UsersLogReadSerializer,
    Roles.MODEL_CONTEXT.lower(): RolesLogReadSerializer
}
