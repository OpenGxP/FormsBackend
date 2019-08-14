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
from urp.models.profile import Profile, ProfileLog
from urp.serializers.profile import ProfileReadWriteSerializer, ProfileLogReadSerializer
from urp.decorators import auth_required

# django imports
from django.core.exceptions import ValidationError
from django.views.decorators.csrf import csrf_protect, ensure_csrf_cookie


# PATCH timezone
@api_view(['PATCH'])
@auth_required(initial_password_check=True)
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


# GET list
@api_view(['GET'])
@auth_required()
@auto_logout()
def profile_log_list(request):
    logs = ProfileLog.objects.filter(username=request.user.username).all()
    serializer = ProfileLogReadSerializer(logs, many=True)
    return Response(serializer.data)


# GET list
@api_view(['GET'])
@auth_required()
@auto_logout()
@ensure_csrf_cookie
def profile_list(request):
    query = Profile.objects.filter(username=request.user.username).all()
    serializer = ProfileReadWriteSerializer(query, many=True)
    return Response(serializer.data)


# GET detail
@api_view(['GET', 'PATCH'])
@auth_required()
@auto_logout()
def profile_detail(request, key):
    @csrf_protect
    def patch(_request):
        _serializer = ProfileReadWriteSerializer(query, data=_request.data, context={'method': 'PATCH',
                                                                                     'function': '',
                                                                                     'user': request.user.username})
        if _serializer.is_valid():
            _serializer.save()
            return Response(_serializer.data)
        return Response(_serializer.errors, status=http_status.HTTP_400_BAD_REQUEST)

    @ensure_csrf_cookie
    def get(_request):
        serializer = ProfileReadWriteSerializer(query)
        return Response(serializer.data)

    try:
        query = Profile.objects.get(key=key, username=request.user.username)
    except Profile.DoesNotExist:
        return Response(status=http_status.HTTP_404_NOT_FOUND)
    except ValidationError:
        return Response(status=http_status.HTTP_400_BAD_REQUEST)

    if request.method == 'GET':
        return get(request)

    elif request.method == 'PATCH':
        return patch(request)
