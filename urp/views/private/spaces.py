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

# app imports
from urp.views.views import auto_logout
from urp.decorators import auth_required, auth_auth_required
from urp.models import Spaces
from urp.serializers.spaces import SpacesReadWriteSerializer, SpacesLogReadSerializer, SpacesDeleteSerializer
from urp.views.base import StandardView


view = StandardView(model=Spaces, ser_rw=SpacesReadWriteSerializer, ser_del=SpacesDeleteSerializer,
                    ser_log=SpacesLogReadSerializer)


@api_view(['GET', 'POST'])
@auth_required()
@auto_logout()
def spaces_list(request):
    return view.list(request)


@api_view(['POST'])
@auth_auth_required()
@auto_logout()
def spaces_list_validate(request):
    return view.list(request, validate_only=True)


@api_view(['GET', 'PATCH', 'DELETE'])
@auth_required()
@auto_logout()
def spaces_detail(request, space):
    return view.detail(request, space)


@api_view(['PATCH'])
@auth_auth_required()
@auto_logout()
def spaces_detail_validate(request, space):
    return view.detail(request, space, validate_only=True)


@api_view(['GET'])
@auth_required()
@auto_logout()
def spaces_log_list(request):
    return view.list_log(request)
