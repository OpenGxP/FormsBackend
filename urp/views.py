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
    RolesWriteSerializer, UsersReadSerializer, RolesDeleteStatusSerializer, RolesNewVersionSerializer, \
    UsersWriteSerializer, UsersNewVersionSerializer, UsersDeleteStatusSerializer
from .decorators import auth_required, perm_required

# django imports
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
@perm_required('01.01')
def status_list(request, format=None):
    """
    List all status.
    """
    stat = Status.objects.all()
    serializer = StatusReadWriteSerializer(stat, many=True)
    return Response(serializer.data)


###############
# PERMISSIONS #
###############

# GET list
@api_view(['GET'])
@auth_required()
@perm_required('02.01')
def permissions_list(request, format=None):
    """
    List all permissions.
    """
    perm = Permissions.objects.all()
    serializer = PermissionsReadWriteSerializer(perm, many=True)
    return Response(serializer.data)


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

    @perm_required('03.02')
    def post(_request):
        # add version for new objects because of combined unique constraint
        _request.data['version'] = 1
        _serializer = RolesWriteSerializer(data=_request.data, context={'method': 'POST',
                                                                        'function': 'new'})
        if _serializer.is_valid():
            _serializer.save()
            return Response(_serializer.data, status=http_status.HTTP_201_CREATED)
        return Response(_serializer.errors, status=http_status.HTTP_400_BAD_REQUEST)

    @perm_required('03.01')
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

    @perm_required('03.03')
    def patch(_request):
        _serializer = RolesWriteSerializer(role, data=_request.data, context={'method': 'PATCH',
                                                                              'function': ''})
        if _serializer.is_valid():
            _serializer.save()
            return Response(_serializer.data)
        return Response(_serializer.errors, status=http_status.HTTP_400_BAD_REQUEST)

    def post_base(_request):
        _serializer = RolesNewVersionSerializer(role, data=_request.data, context={'method': 'POST',
                                                                                   'function': 'new_version'})
        if _serializer.is_valid():
            _serializer.create(validated_data=_serializer.validated_data)
            return Response(_serializer.data, status=http_status.HTTP_201_CREATED)
        return Response(_serializer.errors, status=http_status.HTTP_400_BAD_REQUEST)

    @perm_required('03.11')
    def post(_request):
        return post_base(_request)

    @perm_required('03.12')
    def post_archived(_request):
        return post_base(_request)

    @perm_required('03.04')
    def delete(_request):
        _serializer = RolesDeleteStatusSerializer(role, data={}, context={'method': 'DELETE',
                                                                          'function': ''})
        if _serializer.is_valid():
            _serializer.delete()
            return Response(status=http_status.HTTP_204_NO_CONTENT)
        return Response(_serializer.errors, status=http_status.HTTP_400_BAD_REQUEST)

    @perm_required('03.01')
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
        if role.status.id == Status.objects.archived:
            return post_archived(request)
        else:
            return post(request)

    elif request.method == 'DELETE':
        return delete(request)


@api_view(['PATCH'])
@auth_required()
def roles_status(request, lifecycle_id, version, status, format=None):

    def patch_base(_request):
        _serializer = RolesDeleteStatusSerializer(role, data={}, context={'method': 'PATCH',
                                                                          'function': 'status_change',
                                                                          'status': status})
        if _serializer.is_valid():
            _serializer.save()
            return Response(_serializer.data)
        return Response(_serializer.errors, status=http_status.HTTP_400_BAD_REQUEST)

    @perm_required('03.05')
    def patch_circulation(_request):
        return patch_base(_request)

    @perm_required('03.06')
    def patch_draft(_request):
        return patch_base(_request)

    @perm_required('03.07')
    def patch_productive(_request):
        return patch_base(_request)

    @perm_required('03.08')
    def patch_blocked(_request):
        return patch_base(_request)

    @perm_required('03.09')
    def patch_archived(_request):
        return patch_base(_request)

    @perm_required('03.10')
    def patch_inactive(_request):
        return patch_base(_request)

    try:
        role = Roles.objects.get(lifecycle_id=lifecycle_id, version=version)
    except Roles.DoesNotExist:
        return Response(status=http_status.HTTP_404_NOT_FOUND)
    except ValidationError:
        return Response(status=http_status.HTTP_400_BAD_REQUEST)

    if request.method == 'PATCH':
        if status == 'circulation':
            return patch_circulation(request)
        if status == 'draft':
            return patch_draft(request)
        if status == 'productive':
            return patch_productive(request)
        if status == 'blocked':
            return patch_blocked(request)
        if status == 'archived':
            return patch_archived(request)
        if status == 'inactive':
            return patch_inactive(request)
        return patch_base(request)


#########
# USERS #
#########

# GET list
@api_view(['GET', 'POST'])
@auth_required()
def users_list(request, format=None):
    @perm_required('04.02')
    def post(_request):
        # add version for new objects because of combined unique constraint
        _request.data['version'] = 1
        _serializer = UsersWriteSerializer(data=_request.data, context={'method': 'POST',
                                                                        'function': 'new'})
        if _serializer.is_valid():
            _serializer.save()
            return Response(_serializer.data, status=http_status.HTTP_201_CREATED)
        return Response(_serializer.errors, status=http_status.HTTP_400_BAD_REQUEST)

    @perm_required('04.01')
    def get(_request):
        users = Users.objects.all()
        serializer = UsersReadSerializer(users, many=True)
        return Response(serializer.data)

    if request.method == 'GET':
        return get(request)
    if request.method == 'POST':
        return post(request)


# GET detail
@api_view(['GET', 'POST'])
@auth_required()
def users_detail(request, lifecycle_id, version, format=None):
    @perm_required('04.01')
    def get(_request):
        serializer = UsersReadSerializer(user)
        return Response(serializer.data)

    def post_base(_request):
        _serializer = UsersNewVersionSerializer(user, data=_request.data, context={'method': 'POST',
                                                                                   'function': 'new_version'})
        if _serializer.is_valid():
            _serializer.create(validated_data=_serializer.validated_data)
            return Response(_serializer.data, status=http_status.HTTP_201_CREATED)
        return Response(_serializer.errors, status=http_status.HTTP_400_BAD_REQUEST)

    @perm_required('04.11')
    def post(_request):
        return post_base(_request)

    @perm_required('04.12')
    def post_archived(_request):
        return post_base(_request)

    try:
        user = Users.objects.get(lifecycle_id=lifecycle_id, version=version)
    except Users.DoesNotExist:
        return Response(status=http_status.HTTP_404_NOT_FOUND)
    except ValidationError:
        return Response(status=http_status.HTTP_400_BAD_REQUEST)

    if request.method == 'GET':
        return get(request)
    elif request.method == 'POST':
        if user.status.id == Status.objects.archived:
            return post_archived(request)
        else:
            return post(request)


@api_view(['PATCH'])
@auth_required()
def users_status(request, lifecycle_id, version, status, format=None):

    def patch_base(_request):
        _serializer = UsersDeleteStatusSerializer(user, data={}, context={'method': 'PATCH',
                                                                          'function': 'status_change',
                                                                          'status': status})
        if _serializer.is_valid():
            _serializer.save()
            return Response(_serializer.data)
        return Response(_serializer.errors, status=http_status.HTTP_400_BAD_REQUEST)

    @perm_required('04.05')
    def patch_circulation(_request):
        return patch_base(_request)

    @perm_required('04.06')
    def patch_draft(_request):
        return patch_base(_request)

    @perm_required('04.07')
    def patch_productive(_request):
        return patch_base(_request)

    @perm_required('04.08')
    def patch_blocked(_request):
        return patch_base(_request)

    @perm_required('04.09')
    def patch_archived(_request):
        return patch_base(_request)

    @perm_required('04.10')
    def patch_inactive(_request):
        return patch_base(_request)

    try:
        user = Users.objects.get(lifecycle_id=lifecycle_id, version=version)
    except Users.DoesNotExist:
        return Response(status=http_status.HTTP_404_NOT_FOUND)
    except ValidationError:
        return Response(status=http_status.HTTP_400_BAD_REQUEST)

    if request.method == 'PATCH':
        if status == 'circulation':
            return patch_circulation(request)
        if status == 'draft':
            return patch_draft(request)
        if status == 'productive':
            return patch_productive(request)
        if status == 'blocked':
            return patch_blocked(request)
        if status == 'archived':
            return patch_archived(request)
        if status == 'inactive':
            return patch_inactive(request)
        return patch_base(request)
