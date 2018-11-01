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


# django imports
# from django.http import HttpResponse, Http404

# rest imports
from rest_framework.views import APIView
from rest_framework.response import Response
# from rest_framework import status

# custom imports
from .models import Status, Users, Roles, Permissions
from .serializers import StatusSerializer, PermissionsSerializer, UsersSerializer, RolesSerializer


# status
class StatusList(APIView):
    # list of all status or create new status
    @staticmethod
    def get(request):
        queryset = Status.objects.all()
        serializer = StatusSerializer(queryset, context={'request': request}, many=True)
        return Response(serializer.data)


# permissions
class PermissionsList(APIView):
    # list of all status or create new status
    @staticmethod
    def get(request):
        queryset = Permissions.objects.all()
        serializer = PermissionsSerializer(queryset, context={'request': request}, many=True)
        return Response(serializer.data)


# roles
class RolesList(APIView):
    # list of all status or create new status
    @staticmethod
    def get(request):
        queryset = Roles.objects.all()
        serializer = RolesSerializer(queryset, context={'request': request}, many=True)
        return Response(serializer.data)


# users
class UsersList(APIView):
    # list of all status or create new status
    @staticmethod
    def get(request):
        queryset = Users.objects.all()
        serializer = UsersSerializer(queryset, context={'request': request}, many=True)
        return Response(serializer.data)
