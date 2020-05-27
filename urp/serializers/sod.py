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

# rest imports
from rest_framework import serializers

# app imports
from urp.models.roles import Roles
from urp.models.sod import SoD, SoDLog
from urp.serializers import GlobalReadWriteSerializer


# read / add / edit
class SoDReadWriteSerializer(GlobalReadWriteSerializer):
    status = serializers.CharField(source='get_status', read_only=True)

    class Meta:
        model = SoD
        extra_kwargs = {'version': {'required': False}}
        fields = model.objects.GET_MODEL_ORDER + model.objects.GET_BASE_ORDER_STATUS_MANAGED + \
            model.objects.GET_BASE_CALCULATED + model.objects.COMMENT_SIGNATURE

    # FO-292: moved sod validation to specific serializer to provide error messages on field level
    def validate_base(self, value):
        if not Roles.objects.filter(role=value).exists():
            raise serializers.ValidationError('Role does not exist.')
        return value

    def validate_conflict(self, value):
        if not Roles.objects.filter(role=value).exists():
            raise serializers.ValidationError('Role does not exist.')
        return value

    def validate_post_specific(self, data):
        if not any(e in self.my_errors.keys() for e in self.model.UNIQUE):
            if data['base'] == data['conflict']:
                self.my_errors.update({'base': ['Roles cannot be in self-conflict.']})
                self.my_errors.update({'conflict': ['Roles cannot be in self-conflict.']})


# new version / status
class SoDNewVersionStatusSerializer(GlobalReadWriteSerializer):
    status = serializers.CharField(source='get_status', read_only=True)

    class Meta:
        model = SoD
        extra_kwargs = {'version': {'required': False},
                        'base': {'required': False},
                        'conflict': {'required': False}}
        fields = model.objects.GET_MODEL_ORDER + model.objects.GET_BASE_ORDER_STATUS_MANAGED + \
            model.objects.GET_BASE_CALCULATED + model.objects.COMMENT_SIGNATURE


# delete
class SoDDeleteSerializer(GlobalReadWriteSerializer):
    class Meta:
        model = SoD
        fields = model.objects.COMMENT_SIGNATURE


# read logs
class SoDLogReadSerializer(GlobalReadWriteSerializer):
    status = serializers.CharField(source='get_status', read_only=True)

    class Meta:
        model = SoDLog
        fields = model.objects.GET_MODEL_ORDER + model.objects.GET_BASE_ORDER_STATUS_MANAGED + \
            model.objects.GET_BASE_ORDER_LOG + model.objects.GET_BASE_CALCULATED
