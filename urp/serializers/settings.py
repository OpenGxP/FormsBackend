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
from basics.models import Settings, SettingsLog
from urp.serializers import GlobalReadWriteSerializer


# read / edit
class SettingsReadWriteSerializer(GlobalReadWriteSerializer):
    class Meta:
        model = Settings
        extra_kwargs = {'default': {'read_only': True},
                        'key': {'read_only': True}}
        fields = Settings.objects.GET_MODEL_ORDER + Settings.objects.GET_BASE_CALCULATED + \
            model.objects.COMMENT_SIGNATURE


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
