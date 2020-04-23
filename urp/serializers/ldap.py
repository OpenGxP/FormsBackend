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
from urp.crypto import encrypt
from urp.models.ldap import LDAP, LDAPLog
from urp.serializers import GlobalReadWriteSerializer
from urp.backends.ldap import server_check


# read / add / edit
class LDAPReadWriteSerializer(GlobalReadWriteSerializer):
    certificate = serializers.CharField(write_only=True, required=False, allow_blank=True)

    class Meta:
        model = LDAP
        extra_kwargs = {'password': {'write_only': True}}
        fields = model.objects.GET_MODEL_ORDER + ('certificate',) + model.objects.GET_BASE_CALCULATED + \
            model.objects.COMMENT_SIGNATURE

    @staticmethod
    def group_validation(data):
        flag = 0
        for x in ['base_group', 'filter_group', 'attr_group']:
            if x in data:
                if data[x]:
                    flag += 1
        if flag != 0 and flag != 3:
            raise serializers.ValidationError('Group attributes "base_group", "filter_group" and "attr_group" '
                                              'must all be entered.')

    def validate_post_specific(self, data):
        self.group_validation(data)
        server_check(data)

    def validate_patch_specific(self, data):
        self.group_validation(data)
        server_check(data)

    def create_specific(self, validated_data, obj):
        raw_pw = validated_data['password']
        validated_data['password'] = encrypt(raw_pw)
        return validated_data, obj

    # FO-251: route self_call
    def update_specific(self, validated_data, instance, self_call=None):
        raw_pw = validated_data['password']
        validated_data['password'] = encrypt(raw_pw)
        return validated_data, instance


# delete
class LDAPDeleteSerializer(GlobalReadWriteSerializer):
    class Meta:
        model = LDAP
        fields = model.objects.COMMENT_SIGNATURE


# read logs
class LDAPLogReadSerializer(GlobalReadWriteSerializer):
    class Meta:
        model = LDAPLog
        fields = model.objects.GET_MODEL_ORDER + model.objects.GET_BASE_ORDER_LOG + model.objects.GET_BASE_CALCULATED
