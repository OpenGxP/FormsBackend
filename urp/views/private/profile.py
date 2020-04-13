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
from rest_framework.response import Response
from rest_framework import status as http_status
from rest_framework.decorators import api_view

# app imports
from urp.views.views import auto_logout
from urp.models.profile import Profile
from urp.serializers.profile import ProfileReadWriteSerializer, ProfileLogReadSerializer
from urp.decorators import auth_required
from urp.views.base import UpdateView

# django imports
from django.core.exceptions import ValidationError
from django.views.decorators.csrf import csrf_protect


view = UpdateView(model=Profile, ser_rw=ProfileReadWriteSerializer, ser_log=ProfileLogReadSerializer)


@api_view(['GET'])
@auth_required()
@auto_logout()
def profile_list(request):
    return view.list(request, ext_filter={'username': request.user.username})


@api_view(['GET', 'PATCH'])
@auth_required()
@auto_logout()
def profile_detail(request, key):
    return view.detail(request, key, ext_filter={'username': request.user.username})


@api_view(['GET'])
@auth_required()
@auto_logout()
def profile_log_list(request):
    return view.list_log(request, ext_filter={'username': request.user.username})


# PATCH timezone
@api_view(['PATCH'])
@auth_required()
@auto_logout()
@csrf_protect
def set_timezone_view(request):
    try:
        query = Profile.objects.get(key='loc.timezone', username=request.user.username)
    except Profile.DoesNotExist:
        return Response(status=http_status.HTTP_404_NOT_FOUND)
    except ValidationError:
        return Response(status=http_status.HTTP_400_BAD_REQUEST)

    _serializer = ProfileReadWriteSerializer(query, data=request.data, context={'method': 'PATCH',
                                                                                'function': '',
                                                                                'user': request.user.username})
    if _serializer.is_valid():
        _serializer.save()
        return Response(_serializer.data)
    return Response(_serializer.errors, status=http_status.HTTP_400_BAD_REQUEST)
