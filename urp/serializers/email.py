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

# app imports
from urp.crypto import encrypt
from urp.models.email import Email, EmailLog
from urp.serializers import GlobalReadWriteSerializer


# read / add / edit
class EmailReadWriteSerializer(GlobalReadWriteSerializer):
    class Meta:
        model = Email
        extra_kwargs = {'password': {'write_only': True}}
        fields = model.objects.GET_MODEL_ORDER + model.objects.GET_BASE_CALCULATED + model.objects.COMMENT_SIGNATURE

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
class EmailDeleteSerializer(GlobalReadWriteSerializer):
    class Meta:
        model = Email
        fields = model.objects.COMMENT_SIGNATURE


# read logs
class EmailLogReadSerializer(GlobalReadWriteSerializer):
    class Meta:
        model = EmailLog
        fields = model.objects.GET_MODEL_ORDER + model.objects.GET_BASE_ORDER_LOG + model.objects.GET_BASE_CALCULATED
