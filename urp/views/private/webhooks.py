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

# rest imports
from rest_framework.decorators import api_view

# app imports
from urp.views.views import auto_logout
from urp.models.webhooks import WebHooks
from urp.serializers.webhooks import WebHooksReadWriteSerializer, WebHooksDeleteSerializer, \
    WebHooksNewVersionStatusSerializer, WebHooksLogReadSerializer
from urp.decorators import auth_required, auth_auth_required
from urp.views.base import StatusView


view = StatusView(model=WebHooks, ser_rw=WebHooksReadWriteSerializer, ser_del=WebHooksDeleteSerializer,
                  ser_log=WebHooksLogReadSerializer, ser_st=WebHooksNewVersionStatusSerializer)


@api_view(['GET', 'POST'])
@auth_required()
@auto_logout()
def webhooks_list(request):
    return view.list(request, tags=False)


@api_view(['POST'])
@auth_auth_required()
@auto_logout()
def webhooks_list_validate(request):
    return view.list(request, validate_only=True)


@api_view(['GET', 'PATCH', 'POST', 'DELETE'])
@auth_required()
@auto_logout()
def webhooks_detail(request, lifecycle_id, version):
    return view.detail(request, lifecycle_id, version, tags=False)


@api_view(['PATCH'])
@auth_auth_required()
@auto_logout()
def webhooks_detail_validate(request, lifecycle_id, version):
    return view.detail(request, lifecycle_id, version, validate_only=True)


@api_view(['PATCH'])
@auth_required()
@auto_logout()
def webhooks_status(request, lifecycle_id, version, status):
    return view.status(request, lifecycle_id, version, status)


@api_view(['GET'])
@auth_required()
@auto_logout()
def webhooks_log_list(request):
    return view.list_log(request, tags=False)
