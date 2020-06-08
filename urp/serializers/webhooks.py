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

# app imports
from urp.models.webhooks import WebHooks, WebHooksLog
from urp.models.forms.forms import Forms
from urp.serializers import GlobalReadWriteSerializer
from urp.crypto import encrypt

# rest imports
from rest_framework import serializers
from rest_framework.fields import get_error_detail

# django imports
from django.core.exceptions import ValidationError as DjangoValidationError


# read / add / edit
class WebHooksReadWriteSerializer(GlobalReadWriteSerializer):
    status = serializers.CharField(source='get_status', read_only=True)

    class Meta:
        model = WebHooks
        extra_kwargs = {'version': {'required': False},
                        'token': {'write_only': True,
                                  'required': False}}
        fields = model.objects.GET_MODEL_ORDER + model.objects.GET_BASE_ORDER_STATUS_MANAGED + \
            model.objects.GET_BASE_CALCULATED + model.objects.COMMENT_SIGNATURE

    def validate_form(self, value):
        if value:
            form = Forms.objects.verify_prod_valid(key=value)
            if not form:
                raise serializers.ValidationError('Referenced form "{}" is not valid.'.format(value))
        return value

    def validate_post_specific(self, data):
        if 'token' not in data.keys():
            self.my_errors.update({'token': ['This field is required.']})
        else:
            token_field = self.get_fields()['token']
            try:
                token_field.run_validation(data['token'])
            except DjangoValidationError as exc:
                self.my_errors['token'] = get_error_detail(exc)

    def validate_patch_specific(self, data):
        if 'token' in data.keys():
            token_field = self.get_fields()['token']
            try:
                token_field.run_validation(data['token'])
            except DjangoValidationError as exc:
                self.my_errors['token'] = get_error_detail(exc)

    def create_specific(self, validated_data, obj):
        token = validated_data['token']
        validated_data['token'] = encrypt(token)
        return validated_data, obj

    def update_specific(self, validated_data, instance, self_call=None):
        if 'token' in validated_data.keys():
            token = validated_data['token']
            validated_data['token'] = encrypt(token)
        else:
            validated_data['token'] = getattr(instance, 'token')
        return validated_data, instance


# new version / status
class WebHooksNewVersionStatusSerializer(GlobalReadWriteSerializer):
    status = serializers.CharField(source='get_status', read_only=True)

    class Meta:
        model = WebHooks
        extra_kwargs = {'version': {'required': False},
                        'webhook': {'required': False},
                        'url': {'required': False},
                        'header_token': {'required': False},
                        'form': {'required': False}}
        fields = model.objects.GET_MODEL_ORDER_NO_TOKEN + model.objects.GET_BASE_ORDER_STATUS_MANAGED + \
            model.objects.GET_BASE_CALCULATED + model.objects.COMMENT_SIGNATURE


# delete
class WebHooksDeleteSerializer(GlobalReadWriteSerializer):
    class Meta:
        model = WebHooks
        fields = model.objects.COMMENT_SIGNATURE


# read logs
class WebHooksLogReadSerializer(GlobalReadWriteSerializer):
    status = serializers.CharField(source='get_status', read_only=True)

    class Meta:
        model = WebHooksLog
        fields = model.objects.GET_MODEL_ORDER_NO_TOKEN + model.objects.GET_BASE_ORDER_STATUS_MANAGED + \
            model.objects.GET_BASE_ORDER_LOG + model.objects.GET_BASE_CALCULATED
