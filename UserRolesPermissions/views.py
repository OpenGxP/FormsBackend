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
from django.http import HttpResponse

# rest imports
from rest_framework import viewsets

# custom imports
from .models import Status, Users, Roles, Permissions
from .serializers import StatusSerializer, PermissionsSerializer, UsersSerializer, RolesSerializer


# status
class StatusViewSet(viewsets.ModelViewSet):
    queryset = Status.objects.all()
    serializer_class = StatusSerializer


# permissions
class PermissionsViewSet(viewsets.ModelViewSet):
    queryset = Permissions.objects.all()
    serializer_class = PermissionsSerializer


# users
class UsersViewSet(viewsets.ModelViewSet):
    queryset = Users.objects.all()
    serializer_class = UsersSerializer


# roles
class RolesViewSet(viewsets.ModelViewSet):
    queryset = Roles.objects.all()
    serializer_class = RolesSerializer


"""
# TESTS
def index(request):
    # b = Users.objects.filter(status_id=Status.objects.filter(status='Effective')[0].id).all()
    b = Users.objects.get(pk=1)
    b.status = Status.objects.get(status='Blocked')
    b.save()
    Users.objects.filter(pk=1).update(status=Status.objects.get(status='Blocked'))

    # a = Status.objects.create(status='neu2', checksum='test')
    # a.checksum = 'test2'
    # a.save()

    c = Roles.objects.new(role='all16', status_id=3, version=1)
    permissions = [1, 2, 3]
    for perm in permissions:
        p = Permissions.objects.get(pk=perm)
        c.permissions.add(p)
    c.save()
    return HttpResponse('{} {} {}'.format(a.status, a.checksum, a.id))
    # return HttpResponse(a.status)
"""
