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
from rest_framework import status as http_status
from rest_framework.response import Response
from rest_framework.decorators import api_view

# app imports
from urp.views.views import auto_logout
from urp.decorators import perm_required, auth_required
from urp.models import Spaces, SpacesLog
from urp.serializers import SpacesReadWriteSerializer, SpacesLogReadSerializer, SpacesDeleteSerializer

# django imports
from django.core.exceptions import ValidationError
from django.views.decorators.csrf import csrf_protect, ensure_csrf_cookie


#############
# SPACESLOG #
#############

@api_view(['GET'])
@auth_required()
@auto_logout()
@perm_required('{}.01'.format(SpacesLog.MODEL_ID))
def spaces_log_list(request):
    logs = SpacesLog.objects.all()
    serializer = SpacesLogReadSerializer(logs, many=True, context={'user': request.user.username})
    return Response(serializer.data)


##########
# SPACES #
##########

@api_view(['GET', 'POST'])
@auth_required()
@auto_logout()
def spaces_list(request):
    @perm_required('{}.02'.format(Spaces.MODEL_ID))
    @csrf_protect
    def post(_request):
        _serializer = SpacesReadWriteSerializer(data=_request.data, context={'method': 'POST',
                                                                             'function': 'new',
                                                                             'user': request.user.username})

        if _serializer.is_valid():
            _serializer.save()
            return Response(_serializer.data, status=http_status.HTTP_201_CREATED)
        return Response(_serializer.errors, status=http_status.HTTP_400_BAD_REQUEST)

    @perm_required('{}.01'.format(Spaces.MODEL_ID))
    @ensure_csrf_cookie
    def get(_request):
        query = Spaces.objects.all()
        serializer = SpacesReadWriteSerializer(query, many=True, context={'user': request.user.username})
        return Response(serializer.data)

    if request.method == 'GET':
        return get(request)
    if request.method == 'POST':
        return post(request)


@api_view(['GET', 'PATCH', 'DELETE'])
@auth_required()
@auto_logout()
def spaces_detail(request, space):
    @perm_required('{}.03'.format(Spaces.MODEL_ID))
    @csrf_protect
    def patch(_request):
        _serializer = SpacesReadWriteSerializer(query, data=_request.data, context={'method': 'PATCH',
                                                                                    'function': '',
                                                                                    'user': request.user.username})
        if _serializer.is_valid():
            _serializer.save()
            return Response(_serializer.data)
        return Response(_serializer.errors, status=http_status.HTTP_400_BAD_REQUEST)

    @perm_required('{}.04'.format(Spaces.MODEL_ID))
    @csrf_protect
    def delete(_request):
        _serializer = SpacesDeleteSerializer(query, data={}, context={'method': 'DELETE',
                                                                      'function': '',
                                                                      'user': request.user.username})
        if _serializer.is_valid():
            _serializer.delete()
            return Response(status=http_status.HTTP_204_NO_CONTENT)
        return Response(_serializer.errors, status=http_status.HTTP_400_BAD_REQUEST)

    @perm_required('{}.01'.format(Spaces.MODEL_ID))
    @ensure_csrf_cookie
    def get(_request):
        serializer = SpacesReadWriteSerializer(query, context={'user': request.user.username})
        return Response(serializer.data)

    try:
        query = Spaces.objects.get(space=space)
    except Spaces.DoesNotExist:
        return Response(status=http_status.HTTP_404_NOT_FOUND)
    except ValidationError:
        return Response(status=http_status.HTTP_400_BAD_REQUEST)

    if request.method == 'GET':
        return get(request)

    elif request.method == 'PATCH':
        return patch(request)

    elif request.method == 'DELETE':
        return delete(request)
