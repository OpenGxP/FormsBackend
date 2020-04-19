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
from rest_framework.response import Response
from rest_framework import status as http_status

# custom imports
from urp.serializers.inbox import InboxReadSerializer
from urp.decorators import auth_required, auth_auth_required
from urp.models.inbox import Inbox
from urp.views.base import auto_logout, GET


# GET list
@api_view(['GET'])
@auth_required()
@auto_logout()
def inbox_list(request):
    get = GET(model=Inbox, request=request, serializer=InboxReadSerializer,
              _filter={'users__contains': request.user.username})
    return get.standard


# FO-240: helper view for inbox notification polling only
@api_view(['GET'])
@auth_auth_required()
def inbox_notifications(request):
    count = Inbox.objects.filter(**{'users__contains': request.user.username}).count()
    return Response(data={'notifications': count}, status=http_status.HTTP_200_OK)
