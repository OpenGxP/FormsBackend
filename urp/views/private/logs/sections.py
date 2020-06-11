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
from rest_framework.decorators import api_view

# custom imports
from urp.serializers.logs.sections import ExecutionSectionsLogReadWriteSerializer
from urp.decorators import auth_perm_required
from urp.models.logs.sections import ExecutionSectionsLog
from urp.views.base import auto_logout, GET


# GET list
@api_view(['GET'])
@auth_perm_required(permission='{}.01'.format(ExecutionSectionsLog.MODEL_ID))
@auto_logout()
def execution_sections_log_list(request):
    get = GET(model=ExecutionSectionsLog, request=request, serializer=ExecutionSectionsLogReadWriteSerializer)
    get.tags = True
    return get.standard
