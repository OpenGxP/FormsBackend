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
from urp.models.profile import Profile, ProfileLog
from urp.serializers import GlobalReadWriteSerializer
from basics.custom import value_to_int

# django imports
from django.conf import settings


# read / edit
class ProfileReadWriteSerializer(GlobalReadWriteSerializer):
    class Meta:
        model = Profile
        extra_kwargs = {'username': {'read_only': True},
                        'default': {'read_only': True},
                        'key': {'read_only': True},
                        'human_readable': {'read_only': True}}
        fields = Profile.objects.GET_MODEL_ORDER + Profile.objects.GET_BASE_CALCULATED

    def validate_value(self, value):
        if self.instance.key == 'loc.timezone':
            if value not in settings.PROFILE_TIMEZONES:
                raise serializers.ValidationError('Selected timezone is not supported.')
        elif self.instance.key == 'loc.language':
            if value not in ['en_EN']:
                raise serializers.ValidationError('Selected language is not supported.')
        elif self.instance.key == 'gui.pagination':
            try:
                # try to convert to integer
                value = value_to_int(value)
                # verify that integer is positive
                if value not in settings.PROFILE_PAGINATION_SELECTIONS:
                    raise ValueError
            except ValueError:
                raise serializers.ValidationError('Only following integers are allowed: {}.'
                                                  .format(settings.PROFILE_PAGINATION_SELECTIONS))

        return value


# initial write
class ProfileInitialWriteSerializer(GlobalReadWriteSerializer):
    class Meta:
        model = Profile
        exclude = ('id', 'checksum',)


# read logs
class ProfileLogReadSerializer(GlobalReadWriteSerializer):
    class Meta:
        model = ProfileLog
        fields = ProfileLog.objects.GET_MODEL_ORDER + ProfileLog.objects.GET_BASE_ORDER_LOG + \
            ProfileLog.objects.GET_BASE_CALCULATED
