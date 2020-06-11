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

# custom imports
from urp.models.logs.sections import ExecutionSectionsLog
from urp.serializers import GlobalReadWriteSerializer


# read
class ExecutionSectionsLogReadWriteSerializer(GlobalReadWriteSerializer):
    class Meta:
        model = ExecutionSectionsLog
        fields = ExecutionSectionsLog.objects.GET_MODEL_ORDER + ExecutionSectionsLog.objects.GET_BASE_CALCULATED \
            + ExecutionSectionsLog.objects.GET_BASE_ORDER_LOG
