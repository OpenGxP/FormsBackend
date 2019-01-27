"""
opengxp.org
Copyright (C) 2018  Henrik Baran

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
from rest_framework.reverse import reverse

# custom imports
from .models import Status, Roles, Permissions, Users
from .serializers import StatusReadWriteSerializer, PermissionsReadWriteSerializer, RolesReadSerializer, \
    RolesWriteSerializer, UsersReadSerializer, RolesDeleteStatusSerializer, RolesNewVersionSerializer
from .decorators import auth_required, perm_required

# django imports
from django.views.decorators.csrf import csrf_protect, ensure_csrf_cookie
from django.core.exceptions import ValidationError


########
# ROOT #
########

@api_view(['GET'])
def api_root(request, format=None):
    return Response({
        'status': reverse('status-list', request=request, format=format),
        'permissions': reverse('permissions-list', request=request, format=format),
        'roles': reverse('roles-list', request=request, format=format),
        'users': reverse('users-list', request=request, format=format),
        'token': reverse('token_obtain_pair', request=request, format=format)
    })


##########
# STATUS #
##########

# GET list
@api_view(['GET'])
@auth_required()
@perm_required('st.rea')
def status_list(request, format=None):
    """
    List all status.
    """
    stat = Status.objects.all()
    serializer = StatusReadWriteSerializer(stat, many=True)
    return Response(serializer.data)


# GET detail
"""@api_view(['GET'])
@auth_required()
@perm_required('st.rea')
def status_detail(request, pk, format=None):
    try:
        stat = Status.objects.get(pk=pk)
    except Status.DoesNotExist:
        return Response(status=http_status.HTTP_404_NOT_FOUND)

    serializer = StatusReadWriteSerializer(stat)
    return Response(serializer.data)"""


###############
# PERMISSIONS #
###############

# GET list
@api_view(['GET'])
@auth_required()
@perm_required('pe.rea')
def permissions_list(request, format=None):
    """
    List all permissions.
    """
    perm = Permissions.objects.all()
    serializer = PermissionsReadWriteSerializer(perm, many=True)
    return Response(serializer.data)


# GET detail
"""@api_view(['GET'])
@auth_required()
@perm_required('pe.rea')
def permissions_detail(request, pk, format=None):
    try:
        perm = Permissions.objects.get(pk=pk)
    except Permissions.DoesNotExist:
        return Response(status=http_status.HTTP_404_NOT_FOUND)

    serializer = PermissionsReadWriteSerializer(perm)
    return Response(serializer.data)"""


#########
# ROLES #
#########

# GET list
@api_view(['GET', 'POST'])
@auth_required()
def roles_list(request, format=None):
    """
    List all roles.
    """

    @perm_required('ro.edi')
    @csrf_protect
    def post(_request):
        # add version for new objects because of combined unique constraint
        _request.data['version'] = 1
        _serializer = RolesWriteSerializer(data=_request.data, context={'method': 'POST',
                                                                        'function': 'new'})
        if _serializer.is_valid():
            _serializer.save()
            return Response(_serializer.data, status=http_status.HTTP_201_CREATED)
        return Response(_serializer.errors, status=http_status.HTTP_400_BAD_REQUEST)

    @perm_required('ro.rea')
    @ensure_csrf_cookie
    def get(_request):
        roles = Roles.objects.all()
        serializer = RolesReadSerializer(roles, many=True)
        return Response(serializer.data)

    if request.method == 'GET':
        return get(request)
    if request.method == 'POST':
        return post(request)


# GET detail
@api_view(['GET', 'PATCH', 'POST', 'DELETE'])
@auth_required()
def roles_detail(request, lifecycle_id, version, format=None):
    """
    Retrieve roles.
    """

    @csrf_protect
    def patch(_request):
        _serializer = RolesWriteSerializer(role, data=_request.data, context={'method': 'PATCH',
                                                                              'function': ''})
        if _serializer.is_valid():
            _serializer.save()
            return Response(_serializer.data)
        return Response(_serializer.errors, status=http_status.HTTP_400_BAD_REQUEST)

    @perm_required('ro.ver')
    @csrf_protect
    def post(_request):
        _serializer = RolesNewVersionSerializer(role, data=_request.data, context={'method': 'POST',
                                                                                   'function': 'new_version'})
        if _serializer.is_valid():
            _serializer.create(validated_data=_serializer.validated_data)
            return Response(_serializer.data, status=http_status.HTTP_201_CREATED)
        return Response(_serializer.errors, status=http_status.HTTP_400_BAD_REQUEST)

    @csrf_protect
    def delete(_request):
        _serializer = RolesDeleteStatusSerializer(role, data={}, context={'method': 'DELETE',
                                                                          'function': ''})
        if _serializer.is_valid():
            _serializer.delete()
            return Response(status=http_status.HTTP_204_NO_CONTENT)
        return Response(_serializer.errors, status=http_status.HTTP_400_BAD_REQUEST)

    @perm_required('ro.rea')
    @ensure_csrf_cookie
    def get(_request):
        serializer = RolesReadSerializer(role)
        return Response(serializer.data)

    try:
        role = Roles.objects.get(lifecycle_id=lifecycle_id, version=version)
    except Roles.DoesNotExist:
        return Response(status=http_status.HTTP_404_NOT_FOUND)
    except ValidationError:
        return Response(status=http_status.HTTP_400_BAD_REQUEST)

    if request.method == 'GET':
        return get(request)

    elif request.method == 'PATCH':
        return patch(request)

    elif request.method == 'POST':
        return post(request)

    elif request.method == 'DELETE':
        return delete(request)


@api_view(['PATCH'])
@auth_required()
def roles_status(request, lifecycle_id, version, status, format=None):
    @csrf_protect
    def patch(_request):
        _serializer = RolesDeleteStatusSerializer(role, data={}, context={'method': 'PATCH',
                                                                          'function': 'status_change',
                                                                          'status': status})
        if _serializer.is_valid():
            _serializer.save()
            return Response(_serializer.data)
        return Response(_serializer.errors, status=http_status.HTTP_400_BAD_REQUEST)

    try:
        role = Roles.objects.get(lifecycle_id=lifecycle_id, version=version)
    except Roles.DoesNotExist:
        return Response(status=http_status.HTTP_404_NOT_FOUND)
    except ValidationError:
        return Response(status=http_status.HTTP_400_BAD_REQUEST)

    if request.method == 'PATCH':
        return patch(request)


#########
# USERS #
#########

# GET list
@api_view(['GET'])
@auth_required()
def users_list(request, format=None):
    """
    List all users.
    """

    @perm_required('us.rea')
    @ensure_csrf_cookie
    def get(_request):
        users = Users.objects.all()
        serializer = UsersReadSerializer(users, many=True)
        return Response(serializer.data)

    if request.method == 'GET':
        return get(request)


# GET detail
@api_view(['GET'])
@auth_required()
def users_detail(request, lifecycle_id, version, format=None):
    """
    Retrieve users.
    """

    @perm_required('us.rea')
    @ensure_csrf_cookie
    def get(_request):
        serializer = UsersReadSerializer(user)
        return Response(serializer.data)

    try:
        user = Users.objects.get(lifecycle_id=lifecycle_id, version=version)
    except Users.DoesNotExist:
        return Response(status=http_status.HTTP_404_NOT_FOUND)

    if request.method == 'GET':
        return get(request)
