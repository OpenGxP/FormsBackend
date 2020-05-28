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

# python imports
import binascii
import os

# rest imports
from rest_framework import serializers

# app imports
from urp.crypto import encrypt
from urp.models.securitykeys import SecurityKeys, SecurityKeysLog
from urp.serializers import GlobalReadWriteSerializer
from urp.models.users import Users


# read / add / edit
class SecurityKeysReadWriteSerializer(GlobalReadWriteSerializer):
    security_key = serializers.CharField(source='decrypt_key', read_only=True)

    class Meta:
        model = SecurityKeys
        extra_kwargs = {'security_key': {'read_only': True}}
        fields = model.objects.GET_MODEL_ORDER + model.objects.GET_BASE_CALCULATED + model.objects.COMMENT_SIGNATURE

    def validate_username(self, value):
        if value:
            allowed = Users.objects.get_by_natural_key_productive_list('username')
            for item in allowed:
                if value == item:
                    return value
            raise serializers.ValidationError('Not allowed to use this username.')

    def create_specific(self, validated_data, obj):
        token = binascii.hexlify(os.urandom(20)).decode()
        validated_data['security_key'] = encrypt(token)
        return validated_data, obj


# delete
class SecurityKeysDeleteSerializer(GlobalReadWriteSerializer):
    class Meta:
        model = SecurityKeys
        fields = model.objects.COMMENT_SIGNATURE


# read logs
class SecurityKeysLogReadSerializer(GlobalReadWriteSerializer):
    security_key = serializers.CharField(source='decrypt_key', read_only=True)

    class Meta:
        model = SecurityKeysLog
        fields = model.objects.GET_MODEL_ORDER + model.objects.GET_BASE_ORDER_LOG + model.objects.GET_BASE_CALCULATED
