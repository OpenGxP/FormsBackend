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
from urp.models import Tags
from urp.serializers.tags import TagsReadWriteSerializer, TagsDeleteSerializer, TagsLogReadSerializer
from urp.decorators import auth_required, auth_auth_required

from urp.views.base import auto_logout, StandardView


view = StandardView(model=Tags, ser_rw=TagsReadWriteSerializer, ser_del=TagsDeleteSerializer,
                    ser_log=TagsLogReadSerializer)


@api_view(['GET', 'POST'])
@auth_required()
@auto_logout()
def tags_list(request):
    return view.list(request)


@api_view(['POST'])
@auth_auth_required()
@auto_logout()
def tags_list_validate(request):
    return view.list(request, validate_only=True)


@api_view(['GET', 'PATCH', 'DELETE'])
@auth_required()
@auto_logout()
def tags_detail(request, tag):
    return view.detail(request, tag)


@api_view(['PATCH'])
@auth_auth_required()
@auto_logout()
def tags_detail_validate(request, tag):
    return view.detail(request, tag, validate_only=True)


@api_view(['GET'])
@auth_required()
@auto_logout()
def tags_log_list(request):
    return view.list_log(request)
