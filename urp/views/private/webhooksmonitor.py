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
from urp.serializers.webhooksmonitor import WebHooksMonitorLogReadSerializer, WebHooksMonitorReadWriteSerializer
from urp.decorators import auth_perm_required
from urp.models.webhooksmonitor import WebHooksMonitor, WebHooksMonitorLog
from urp.views.base import auto_logout, GET


# GET list
@api_view(['GET'])
@auth_perm_required(permission='{}.01'.format(WebHooksMonitor.MODEL_ID))
@auto_logout()
def webhooksmonitor_list(request):
    get = GET(model=WebHooksMonitor, request=request, serializer=WebHooksMonitorReadWriteSerializer)
    return get.standard


# GET list
@api_view(['GET'])
@auth_perm_required(permission='{}.01'.format(WebHooksMonitorLog.MODEL_ID))
@auto_logout()
def webhooksmonitor_log_list(request):
    get = GET(model=WebHooksMonitorLog, request=request, serializer=WebHooksMonitorLogReadSerializer)
    return get.standard
