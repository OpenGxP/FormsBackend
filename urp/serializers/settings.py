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
from urp.models.settings import Settings, SettingsLog
from urp.serializers import GlobalReadWriteSerializer
from basics.custom import value_to_int
from urp.models.users import Users

# django imports
from django.conf import settings
from django.core.validators import validate_email


# read / edit
class SettingsReadWriteSerializer(GlobalReadWriteSerializer):
    lookup = serializers.CharField(read_only=True)

    class Meta:
        model = Settings
        extra_kwargs = {'default': {'read_only': True},
                        'key': {'read_only': True}}
        fields = Settings.objects.GET_MODEL_ORDER + Settings.objects.GET_BASE_CALCULATED + \
            model.objects.COMMENT_SIGNATURE + ('lookup',)

    def validate_value(self, value):
        # validate maximum login attempts and maximum inactive time and run time data number range start
        if self.instance.key == 'auth.max_login_attempts' or self.instance.key == 'core.auto_logout' \
                or self.instance.key == 'core.password_reset_time' or self.instance.key == 'rtd.number_range':
            try:
                # try to convert to integer
                value = value_to_int(value)
                # verify that integer is positive
                if self.instance.key == 'rtd.number_range':
                    # 0 is allowed as number range
                    if value < 0:
                        raise ValueError
                else:
                    if value < 1:
                        raise ValueError
            except ValueError:
                raise serializers.ValidationError('A valid positive integer is required.')

        # FO-177: added validation for sender email setting
        elif self.instance.key == 'email.sender':
            validate_email(value)

        # validate profile timezone default
        elif self.instance.key == 'profile.default.timezone':
            if value not in settings.SETTINGS_TIMEZONES:
                raise serializers.ValidationError('Selected timezone is not supported.')

        # validate allowed settings for signatures and comments
        elif 'dialog' in self.instance.key:
            if 'signature' in self.instance.key:
                if value not in self.model.ALLOWED_SIGNATURE:
                    raise serializers.ValidationError('Only "logging" and "signature" are allowed.')
            elif 'comment' in self.instance.key:
                if value not in self.model.ALLOWED_COMMENT:
                    raise serializers.ValidationError('Only "none", "optional" and "mandatory" are allowed.')

        # FO-279: validate if name is an existing user
        elif self.instance.key == 'core.system_username':
            if Users.objects.filter(**{Users.UNIQUE: value}).exists():
                raise serializers.ValidationError('System user cannot be named like a real user.')

        return value


# initial write
class SettingsInitialWriteSerializer(GlobalReadWriteSerializer):
    class Meta:
        model = Settings
        exclude = ('id', 'checksum',)


# read logs
class SettingsLogReadSerializer(GlobalReadWriteSerializer):
    class Meta:
        model = SettingsLog
        fields = Settings.objects.GET_MODEL_ORDER + Settings.objects.GET_BASE_ORDER_LOG + \
            Settings.objects.GET_BASE_CALCULATED
