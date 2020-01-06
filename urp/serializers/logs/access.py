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
from urp.models.access import AccessLog
from urp.serializers import GlobalReadWriteSerializer
from urp.custom import create_central_log_record


# read
class AccessLogReadWriteSerializer(GlobalReadWriteSerializer):
    class Meta:
        model = AccessLog
        fields = AccessLog.objects.GET_MODEL_ORDER + AccessLog.objects.GET_BASE_CALCULATED

    def create_specific(self, validated_data, obj):
        create_central_log_record(log_id=obj.id, now=validated_data['timestamp'], context=self.model.MODEL_CONTEXT,
                                  action=validated_data['action'], user=validated_data['user'])
        return validated_data, obj
