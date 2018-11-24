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

# python imports
import uuid

# django imports
from django.urls import reverse

# rest framework imports
from rest_framework import status
from rest_framework.test import APITestCase, APIClient

# app imports
from ..models import Status, Permissions, Roles, Users
from ..serializers import StatusReadSerializer, PermissionsReadSerializer


class Prerequisites(object):
    def __init__(self):
        self.token = uuid.uuid4()
        self.uuid_role = uuid.uuid4()
        self.uuid_user = uuid.uuid4()
        self.username = 'superuser'
        self.password = 'test1234'

    # status
    @staticmethod
    def status():
        Status.objects.create(status='draft', checksum='tbd')
        Status.objects.create(status='circulation', checksum='tbd')
        Status.objects.create(status='productive', checksum='tbd')
        Status.objects.create(status='blocked', checksum='tbd')
        Status.objects.create(status='inactive', checksum='tbd')
        Status.objects.create(status='archived', checksum='tbd')

    # permissions
    @staticmethod
    def permissions():
        Permissions.objects.create(permission='read', key='ro.re', dialog='roles')

    # roles
    def roles(self):
        Roles.objects.create(role='all', status='productive', checksum='tbd', version=1, lifecycle_id=self.uuid_role,
                             permissions='ro.re')

    def users(self):
        Users.objects.create_superuser(username=self.username, password=self.password)

    def auth(self, ext_client):
        data = {'username': self.username, 'password': self.password}
        client = APIClient()
        response = client.post(path=reverse('token_obtain_pair'), data=data, format='json')
        ext_client.credentials(HTTP_AUTHORIZATION='Bearer ' + response.data['access'])


class Authenticate(APITestCase):
    """Test module for authentication"""
    def __init__(self, *args, **kwargs):
        super(Authenticate, self).__init__(*args, **kwargs)
        self.prerequisites = Prerequisites()

    def setUp(self):
        self.prerequisites.status()
        self.prerequisites.users()

    def test_authenticate_false(self):
        # get API response
        data = {'username': 'asdasdasd', 'password': 'sadasdasd'}
        response = self.client.post(reverse('token_obtain_pair'), data=data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_authenticate_positive(self):
        # get API response
        data = {'username': self.prerequisites.username, 'password': self.prerequisites.password}
        response = self.client.post(reverse('token_obtain_pair'), data=data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)


class GetAllStatus(APITestCase):
    """Test module for get all status"""
    def __init__(self, *args, **kwargs):
        super(GetAllStatus, self).__init__(*args, **kwargs)
        self.prerequisites = Prerequisites()

    def setUp(self):
        self.prerequisites.status()
        self.prerequisites.users()

    def test_authenticate_status(self):
        # get API response
        response = self.client.get(reverse('status-list'), format='json')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_get_all_status(self):
        # authenticate
        self.prerequisites.auth(self.client)
        # get API response
        response = self.client.get(reverse('status-list'), format='json')
        # get data from db
        _status = Status.objects.all()
        serializer = StatusReadSerializer(_status, many=True)
        self.assertEqual(response.data, serializer.data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)


class GetAllPermissions(APITestCase):
    """Test module for get all permissions"""
    def __init__(self, *args, **kwargs):
        super(GetAllPermissions, self).__init__(*args, **kwargs)
        self.prerequisites = Prerequisites()

    def setUp(self):
        self.prerequisites.status()
        self.prerequisites.users()
        self.prerequisites.permissions()

    def test_authenticate_permissions(self):
        # get API response
        response = self.client.get(reverse('permissions-list'), format='json')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_get_all_permissions(self):
        # authenticate
        self.prerequisites.auth(self.client)
        # get API response
        response = self.client.get(reverse('permissions-list'), format='json')
        # get data from db
        permissions = Permissions.objects.all()
        serializer = PermissionsReadSerializer(permissions, many=True)
        self.assertEqual(response.data, serializer.data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
