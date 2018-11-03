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
from rest_framework import status
from rest_framework.decorators import api_view
from rest_framework.reverse import reverse

# custom imports
from .models import Status, Roles, Permissions, Users
from .serializers import StatusReadSerializer, PermissionsReadSerializer, RolesReadSerializer, \
    SubRolesWriteSerializer, UsersReadSerializer


########
# ROOT #
########

@api_view(['GET'])
def api_root(request, format=None):
    return Response({
        'status': reverse('status-list', request=request, format=format),
        'permissions': reverse('permissions-list', request=request, format=format),
        'roles': reverse('roles-list', request=request, format=format),
        'users': reverse('users-list', request=request, format=format)
    })


##########
# STATUS #
##########

# GET list
@api_view(['GET'])
def status_list(request, format=None):
    """
    List all status.
    """
    stat = Status.objects.all()
    serializer = StatusReadSerializer(stat, many=True)
    return Response(serializer.data)


# GET detail
@api_view(['GET'])
def status_detail(request, pk, format=None):
    """
    Retrieve status.
    """
    try:
        stat = Status.objects.get(pk=pk)
    except Status.DoesNotExist:
        return Response(status=status.HTTP_404_NOT_FOUND)

    serializer = StatusReadSerializer(stat)
    return Response(serializer.data)


###############
# PERMISSIONS #
###############

# GET list
@api_view(['GET'])
def permissions_list(request, format=None):
    """
    List all permissions.
    """
    perm = Permissions.objects.all()
    serializer = PermissionsReadSerializer(perm, many=True)
    return Response(serializer.data)


# GET detail
@api_view(['GET'])
def permissions_detail(request, pk, format=None):
    """
    Retrieve permissions.
    """
    try:
        perm = Permissions.objects.get(pk=pk)
    except Status.DoesNotExist:
        return Response(status=status.HTTP_404_NOT_FOUND)

    serializer = PermissionsReadSerializer(perm)
    return Response(serializer.data)


#########
# ROLES #
#########

# GET list
@api_view(['GET', 'POST'])
def roles_list(request, format=None):
    """
    List all roles.
    """
    if request.method == 'GET':
        roles = Roles.objects.all()
        serializer = RolesReadSerializer(roles, many=True)
        return Response(serializer.data)
    if request.method == 'POST':
        serializer = SubRolesWriteSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# GET detail
@api_view(['GET'])
def roles_detail(request, pk, format=None):
    """
    Retrieve roles.
    """
    try:
        role = Roles.objects.get(pk=pk)
    except Status.DoesNotExist:
        return Response(status=status.HTTP_404_NOT_FOUND)

    serializer = RolesReadSerializer(role)
    return Response(serializer.data)


#########
# USERS #
#########

# GET list
@api_view(['GET'])
def users_list(request, format=None):
    """
    List all users.
    """
    users = Users.objects.all()
    serializer = UsersReadSerializer(users, many=True)
    return Response(serializer.data)


# GET detail
@api_view(['GET'])
def users_detail(request, pk, format=None):
    """
    Retrieve users.
    """
    try:
        stat = Users.objects.get(pk=pk)
    except Status.DoesNotExist:
        return Response(status=status.HTTP_404_NOT_FOUND)

    serializer = UsersReadSerializer(stat)
    return Response(serializer.data)
