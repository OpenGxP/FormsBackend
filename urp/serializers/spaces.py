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
from urp.models.spaces import Spaces, SpacesLog
from urp.models.users import Users
from urp.models.tags import Tags
from urp.serializers import GlobalReadWriteSerializer


# read / add / edit
class SpacesReadWriteSerializer(GlobalReadWriteSerializer):
    class Meta:
        model = Spaces
        fields = model.objects.GET_MODEL_ORDER + model.objects.GET_BASE_CALCULATED

    def validate_users(self, value):
        allowed = Users.objects.get_by_natural_key_productive_list('username')
        value_list = value.split(',')
        for item in value_list:
            if item not in allowed:
                raise serializers.ValidationError('Not allowed to use "{}".'.format(item))
        return value

    def validate_tags(self, value):
        allowed = Tags.objects.get_by_natural_key_productive_list('tag')
        value_list = value.split(',')
        for item in value_list:
            if item not in allowed:
                raise serializers.ValidationError('Not allowed to use "{}".'.format(item))
        return value


# delete
class SpacesDeleteSerializer(GlobalReadWriteSerializer):
    class Meta:
        model = Spaces
        fields = ()


# read logs
class SpacesLogReadSerializer(GlobalReadWriteSerializer):
    class Meta:
        model = SpacesLog
        fields = model.objects.GET_MODEL_ORDER + model.objects.GET_BASE_ORDER_LOG + model.objects.GET_BASE_CALCULATED
