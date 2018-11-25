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
from ..serializers import StatusReadSerializer, PermissionsReadSerializer, RolesReadSerializer


class Prerequisites(object):
    def __init__(self):
        self.token = uuid.uuid4()
        self.role_uuid = uuid.uuid4()
        self.role_version = 1
        self.user_uuid = uuid.uuid4()
        self.username = 'superuser'
        self.password = 'test1234'
        self.status_productive = None

    # status
    def status(self):
        Status.objects.create(status='draft', checksum='tbd')
        Status.objects.create(status='circulation', checksum='tbd')
        self.status_productive = Status.objects.create(status='productive', checksum='tbd').id
        Status.objects.create(status='blocked', checksum='tbd')
        Status.objects.create(status='inactive', checksum='tbd')
        Status.objects.create(status='archived', checksum='tbd')

    # permissions
    @staticmethod
    def permissions():
        Permissions.objects.create(permission='read', key='ro.re', dialog='roles')

    # roles
    def roles(self):
        Roles.objects.create(role='all', status_id=self.status_productive, checksum='tbd', version=self.role_version,
                             lifecycle_id=self.role_uuid, permissions='ro.re')

    def users(self):
        Users.objects.create_superuser(username=self.username, password=self.password)

    def auth(self, ext_client):
        data = {'username': self.username, 'password': self.password}
        client = APIClient()
        response = client.post(path=reverse('token_obtain_pair'), data=data, format='json')
        ext_client.credentials(HTTP_AUTHORIZATION='Bearer ' + response.data['access'])

    @staticmethod
    def csrf(response):
        return response.cookies['csrftoken']


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


class GetStatus(APITestCase):
    """Test module for get all status"""
    def __init__(self, *args, **kwargs):
        super(GetStatus, self).__init__(*args, **kwargs)
        self.prerequisites = Prerequisites()

    def setUp(self):
        self.prerequisites.status()
        self.prerequisites.users()

    def test_status_authenticate_false(self):
        # get API response
        response = self.client.get(reverse('status-list'), format='json')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_status_get_all_positive(self):
        # authenticate
        self.prerequisites.auth(self.client)
        # get API response
        response = self.client.get(reverse('status-list'), format='json')
        # get data from db
        query = Status.objects.all()
        serializer = StatusReadSerializer(query, many=True)
        self.assertEqual(response.data, serializer.data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)


class GetPermissions(APITestCase):
    """Test module for get all permissions"""
    def __init__(self, *args, **kwargs):
        super(GetPermissions, self).__init__(*args, **kwargs)
        self.prerequisites = Prerequisites()

    def setUp(self):
        self.prerequisites.status()
        self.prerequisites.users()
        self.prerequisites.permissions()

    def test_permissions_authenticate_false(self):
        # get API response
        response = self.client.get(reverse('permissions-list'), format='json')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_permissions_get_all_positive(self):
        # authenticate
        self.prerequisites.auth(self.client)
        # get API response
        response = self.client.get(reverse('permissions-list'), format='json')
        # get data from db
        query = Permissions.objects.all()
        serializer = PermissionsReadSerializer(query, many=True)
        self.assertEqual(response.data, serializer.data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)


class GetRoles(APITestCase):
    """Test module for get all permissions"""
    def __init__(self, *args, **kwargs):
        super(GetRoles, self).__init__(*args, **kwargs)
        self.prerequisites = Prerequisites()

    def setUp(self):
        self.prerequisites.status()
        self.prerequisites.users()
        self.prerequisites.permissions()
        self.prerequisites.roles()

    def test_roles_authenticate_false(self):
        # get API response
        response = self.client.get(reverse('roles-list'), format='json')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_roles_get_all_csrf_positive(self):
        # authenticate
        self.prerequisites.auth(self.client)
        # get API response
        response = self.client.get(reverse('roles-list'), format='json')
        self.assertIsNotNone(self.prerequisites.csrf(response))

    def test_roles_get_all_positive(self):
        # authenticate
        self.prerequisites.auth(self.client)
        # get API response
        response = self.client.get(reverse('roles-list'), format='json')
        # get data from db
        query = Roles.objects.all()
        serializer = RolesReadSerializer(query, many=True)
        self.assertEqual(response.data, serializer.data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_roles_get_one_csrf_positive(self):
        # authenticate
        self.prerequisites.auth(self.client)
        # get API response
        path = '{}{}/{}'.format(reverse('roles-list'), self.prerequisites.role_uuid, self.prerequisites.role_version)
        response = self.client.get(path, format='json')
        self.assertIsNotNone(self.prerequisites.csrf(response))

    def test_roles_get_one_positive(self):
        # authenticate
        self.prerequisites.auth(self.client)
        # get API response
        path = '{}{}/{}'.format(reverse('roles-list'), self.prerequisites.role_uuid, self.prerequisites.role_version)
        response = self.client.get(path, format='json')
        # get data from db
        query = Roles.objects.get(lifecycle_id=self.prerequisites.role_uuid, version=self.prerequisites.role_version)
        serializer = RolesReadSerializer(query)
        self.assertEqual(response.data, serializer.data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_roles_get_one_false_not_found(self):
        # authenticate
        self.prerequisites.auth(self.client)
        # get API response
        path = '{}{}/{}'.format(reverse('roles-list'), self.prerequisites.role_uuid, 2)
        response = self.client.get(path, format='json')
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_roles_get_one_false_syntax_uuid(self):
        # authenticate
        self.prerequisites.auth(self.client)
        # get API response
        path = '{}{}/{}'.format(reverse('roles-list'), '34faf5b2-02bb-4649-b1ef-', self.prerequisites.role_version)
        response = self.client.get(path, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_roles_get_one_false_syntax_version(self):
        # authenticate
        self.prerequisites.auth(self.client)
        # get API response
        path = '{}{}/{}'.format(reverse('roles-list'), self.prerequisites.role_uuid, 'adasdw')
        response = self.client.get(path, format='json')
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
