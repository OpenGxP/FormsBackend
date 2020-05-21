"""
opengxp.org
Copyright (C) 2020 Henrik Baran

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
from urp.vault import create_update_vault
from urp.serializers import GlobalReadWriteSerializer
from urp.models.profile import Profile
from urp.models.vault import Vault
from urp.models.ldap import LDAP
from urp.vault import validate_password_input
from urp.models.settings import Settings


# read / add / edit
class UsersReadWriteSerializer(GlobalReadWriteSerializer):
    status = serializers.CharField(source='get_status', read_only=True)
    password_verification = serializers.CharField(write_only=True, required=False)

    class Meta:
        model = Users
        extra_kwargs = {'version': {'required': False},
                        'initial_password': {'read_only': True},
                        'password': {'write_only': True,
                                     'required': False},
                        'external': {'required': False},
                        'roles': {'required': True}}
        fields = model.objects.GET_MODEL_ORDER + model.objects.GET_BASE_ORDER_STATUS_MANAGED + \
            model.objects.GET_BASE_CALCULATED + ('password_verification',) + model.objects.COMMENT_SIGNATURE

    # FO-279: validate is username is currently configured as system user
    def validate_username(self, value):
        if value == Settings.objects.core_system_username:
            raise serializers.ValidationError('This username is not allowed, because it is used for the system user.')
        return value

    def validate_roles(self, value):
        allowed = Roles.objects.get_by_natural_key_productive_list('role')
        value_list = value.split(',')
        for item in value_list:
            if item not in allowed:
                raise serializers.ValidationError('Not allowed to use "{}".'.format(item))
        return value

    # FO-156: for user updates email shall only be used by own lifecycle record, not by other users
    def validate_email(self, value):
        if not self.instance:
            if Users.objects.filter(email__contains=value):
                raise serializers.ValidationError('Email is is use by another user used.')
        else:
            references = Users.objects.filter(email__contains=value).values_list('lifecycle_id', flat=True)
            for ref in references:
                if self.instance:
                    if ref != self.instance.lifecycle_id:
                        raise serializers.ValidationError('Email is is used by another user.')
        return value

    def validate_external(self, value):
        if self.instance:
            if self.instance.external != value:
                raise serializers.ValidationError('Value of this field can not be changed.')
        return value

    def validate_ldap(self, value):
        if value:
            # in case a password was passed, set to none
            self.initial_data['password'] = ''
            LDAP.objects.search_user(self.initial_data)

        return value

    def validate_post_specific(self, data):
        data['external'] = False

        # FO-143: password check for non-ldap managed users only
        if 'ldap' not in self.my_errors.keys():
            if not data['ldap']:
                # perform password check
                try:
                    validate_password_input(data=data, initial=True)
                except serializers.ValidationError as e:
                    self.my_errors.update(e.detail)

    def validate_patch_specific(self, data):
        if 'ldap' not in self.my_errors.keys():
            if not data['ldap']:
                # if previous record was ldap managed, fore password check
                if self.instance.ldap:
                    try:
                        validate_password_input(data=data, initial=True)
                    except serializers.ValidationError as e:
                        self.my_errors.update(e.detail)
                # if previous record was not ldap managed, make password change optional
                else:
                    if data['password'] if 'password' in data.keys() else None:
                        try:
                            validate_password_input(data=data, initial=True)
                        except serializers.ValidationError as e:
                            self.my_errors.update(e.detail)

    def create_specific(self, validated_data, obj):
        if self.context['function'] == 'new_version':
            # use users initial_password property method
            validated_data['initial_password'] = self.instance.initial_password
        else:
            # add is_active because django framework needs it
            validated_data['is_active'] = True
            # default initial password is false for ldap (initial_password required for log record)
            validated_data['initial_password'] = False

            # if not ldap managed user create vault record
            if not validated_data['ldap']:
                # default initial password for not ldap managed users is true
                validated_data['initial_password'] = True

                # create vault record
                create_update_vault(data=validated_data, log=False, initial=True, signature=self.signature,
                                    now=self.now)

            # create profile
            Profile.objects.generate_profile(username=validated_data['username'], log_user=self.context['user'])

        return validated_data, obj

    # FO-251: route self_call
    def update_specific(self, validated_data, instance, self_call=None):
        # draft updates shall be reflected in vault
        if not validated_data['ldap']:
            # check if previous record was ldap managed
            if instance.ldap:
                # create new vault, because now is password managed
                create_update_vault(data=validated_data, log=False, initial=True, signature=self.signature,
                                    now=self.now)
            else:
                # get existing vault for that user
                vault = Vault.objects.filter(username=instance.username).get()

                # update vault
                create_update_vault(data=validated_data, instance=vault, log=False, initial=True,
                                    signature=self.signature, now=self.now)

        else:
            # check if previous record was ldap managed
            if not instance.ldap:
                # delete existing vault for that user because not password managed anymore
                Vault.objects.filter(username=instance.username).delete()

        return validated_data, instance


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
                        'ldap': {'required': False},
                        'external': {'required': False}}
        fields = Users.objects.GET_MODEL_ORDER_NO_PW + Users.objects.GET_BASE_ORDER_STATUS_MANAGED + \
            Users.objects.GET_BASE_CALCULATED + model.objects.COMMENT_SIGNATURE


# delete
class UsersDeleteSerializer(GlobalReadWriteSerializer):
    class Meta:
        model = Users
        fields = model.objects.COMMENT_SIGNATURE

    def delete_specific(self, fields):
        if not self.instance.ldap:
            # add initial password to validated data for logging
            vault = Vault.objects.filter(username=self.instance.username).get()
            fields['initial_password'] = vault.initial_password
        else:
            fields['initial_password'] = False
        # FO-140: delete vault record after deleting object, only for version 1
        if not self.instance.ldap and self.instance.version == 1:
            vault = Vault.objects.filter(username=self.instance.username).get()
            vault.delete()

        # delete profile
        Profile.objects.delete_profile(username=self.instance.username, log_user=self.context['user'])

        return fields


# read logs
class UsersLogReadSerializer(GlobalReadWriteSerializer):
    status = serializers.CharField(source='get_status')

    class Meta:
        model = UsersLog
        fields = UsersLog.objects.GET_MODEL_ORDER_NO_PW + ('initial_password',) + \
            Users.objects.GET_BASE_ORDER_STATUS_MANAGED + UsersLog.objects.GET_BASE_ORDER_LOG + \
            UsersLog.objects.GET_BASE_CALCULATED
