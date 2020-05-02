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

# django imports
from django.conf import settings

# rest imports
from rest_framework import serializers

# app imports
from urp.decorators import require_NONE, require_NEW
from urp.models.roles import Roles, RolesLog
from urp.serializers import GlobalReadWriteSerializer


# read / add / edit
class RolesReadWriteSerializer(GlobalReadWriteSerializer):
    status = serializers.CharField(source='get_status', read_only=True)

    class Meta:
        model = Roles
        extra_kwargs = {'version': {'required': False},
                        'ldap': {'required': False}}
        fields = Roles.objects.GET_MODEL_ORDER + Roles.objects.GET_BASE_ORDER_STATUS_MANAGED + \
            Roles.objects.GET_BASE_CALCULATED + model.objects.COMMENT_SIGNATURE

    @staticmethod
    def _validate_admin_permissions(data):
        # only check if permission in payload
        if 'permissions' in data.keys():
            # validate if all permission is mixed with other perms
            perms = data['permissions'].split(',')
            if settings.ALL_PERMISSIONS in perms and len(perms) > 1:
                raise serializers.ValidationError('All permissions can not be mixed with regular permissions.')

    @require_NEW
    def _validate_new_admin_permissions(self, data):
        self._validate_admin_permissions(data)

    @require_NONE
    def _validate_update_admin_permissions(self, data):
        self._validate_admin_permissions(data)

    def validate_post_specific(self, data):
        # validate permissions for all mixing
        self._validate_new_admin_permissions(data)

        if self.context['request'].get_full_path().endswith('ldap'):
            data['ldap'] = True
        else:
            data['ldap'] = False

    def validate_patch_specific(self, data):
        # validate permissions for all mixing
        self._validate_update_admin_permissions(data)

        if self.instance.ldap:
            if getattr(self.instance, self.model.UNIQUE) != data[self.model.UNIQUE]:
                raise serializers.ValidationError('Role name can not be changed if LDAP.')
        if 'ldap' in data:
            if self.instance.ldap != data['ldap']:
                raise serializers.ValidationError('LDAP attribute can not be changed.')


# new version / status
class RolesNewVersionStatusSerializer(GlobalReadWriteSerializer):
    status = serializers.CharField(source='get_status', read_only=True)

    class Meta:
        model = Roles
        extra_kwargs = {'version': {'required': False},
                        'role': {'required': False},
                        'ldap': {'required': False}}
        fields = Roles.objects.GET_MODEL_ORDER + Roles.objects.GET_BASE_ORDER_STATUS_MANAGED + \
            Roles.objects.GET_BASE_CALCULATED + model.objects.COMMENT_SIGNATURE


# delete
class RolesDeleteSerializer(GlobalReadWriteSerializer):
    class Meta:
        model = Roles
        fields = model.objects.COMMENT_SIGNATURE


# read logs
class RolesLogReadSerializer(GlobalReadWriteSerializer):
    status = serializers.CharField(source='get_status')

    class Meta:
        model = RolesLog
        fields = Roles.objects.GET_MODEL_ORDER + Roles.objects.GET_BASE_ORDER_STATUS_MANAGED + \
            Roles.objects.GET_BASE_ORDER_LOG + Roles.objects.GET_BASE_CALCULATED
