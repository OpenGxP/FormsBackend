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
from urp.models.roles import Roles, RolesLog
from urp.serializers import GlobalReadWriteSerializer


# read / add / edit
class RolesReadWriteSerializer(GlobalReadWriteSerializer):
    status = serializers.CharField(source='get_status', read_only=True)

    class Meta:
        model = Roles
        extra_kwargs = {'version': {'required': False}}
        fields = Roles.objects.GET_MODEL_ORDER + Roles.objects.GET_BASE_ORDER_STATUS_MANAGED + \
            Roles.objects.GET_BASE_CALCULATED


# new version / status
class RolesNewVersionStatusSerializer(GlobalReadWriteSerializer):
    status = serializers.CharField(source='get_status', read_only=True)

    class Meta:
        model = Roles
        extra_kwargs = {'version': {'required': False},
                        'role': {'required': False}}
        fields = Roles.objects.GET_MODEL_ORDER + Roles.objects.GET_BASE_ORDER_STATUS_MANAGED + \
            Roles.objects.GET_BASE_CALCULATED


# delete
class RolesDeleteSerializer(GlobalReadWriteSerializer):
    class Meta:
        model = Roles
        fields = ()


# read logs
class RolesLogReadSerializer(GlobalReadWriteSerializer):
    status = serializers.CharField(source='get_status')

    class Meta:
        model = RolesLog
        fields = Roles.objects.GET_MODEL_ORDER + Roles.objects.GET_BASE_ORDER_STATUS_MANAGED + \
            Roles.objects.GET_BASE_ORDER_LOG + Roles.objects.GET_BASE_CALCULATED
