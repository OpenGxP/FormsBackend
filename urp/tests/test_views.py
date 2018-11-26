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
from django.urls import reverse

# rest framework imports
from rest_framework import status
from rest_framework.test import APITestCase, APIClient

# app imports
from ..models import Status, Permissions, Roles, Users
from ..serializers import StatusReadSerializer, PermissionsReadSerializer, RolesReadSerializer


class Prerequisites(object):
    def __init__(self, base_path=None):
        self.username = 'superuser'
        self.password = 'test1234'
        self.base_path = base_path

    def superuser(self):
        Users.objects.create_superuser(username=self.username, password=self.password)

    def auth(self, ext_client):
        data = {'username': self.username, 'password': self.password}
        client = APIClient()
        response = client.post(path=reverse('token_obtain_pair'), data=data, format='json')
        ext_client.credentials(HTTP_AUTHORIZATION='Bearer ' + response.data['access'])

    @staticmethod
    def verify_csrf(response):
        return response.cookies['csrftoken']

    def get_csrf(self, ext_client):
        response = ext_client.get(self.base_path, format='json')
        assert response.status_code == status.HTTP_200_OK
        return response.cookies['csrftoken'].value


class Authenticate(APITestCase):
    def __init__(self, *args, **kwargs):
        super(Authenticate, self).__init__(*args, **kwargs)
        self.prerequisites = Prerequisites()
        self.path = reverse('token_obtain_pair')

    fixtures = ['status', 'roles']

    def setUp(self):
        self.prerequisites.superuser()

    def test_400(self):
        # get API response
        data = {'username': 'asdasdasd', 'password': 'sadasdasd'}
        response = self.client.post(self.path, data=data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_200(self):
        # get API response
        data = {'username': self.prerequisites.username, 'password': self.prerequisites.password}
        response = self.client.post(self.path, data=data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)


############
# /status/ #
############

# get
class GetStatus(APITestCase):
    def __init__(self, *args, **kwargs):
        super(GetStatus, self).__init__(*args, **kwargs)
        self.path = reverse('status-list')
        self.prerequisites = Prerequisites()

    fixtures = ['status']

    def setUp(self):
        self.prerequisites.superuser()

    def test_401(self):
        # get API response
        response = self.client.get(self.path, format='json')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_200(self):
        # authenticate
        self.prerequisites.auth(self.client)
        # get API response
        response = self.client.get(self.path, format='json')
        # get data from db
        query = Status.objects.all()
        serializer = StatusReadSerializer(query, many=True)
        self.assertEqual(response.data, serializer.data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)


#################
# /permissions/ #
#################

# get
class GetPermissions(APITestCase):
    def __init__(self, *args, **kwargs):
        super(GetPermissions, self).__init__(*args, **kwargs)
        self.path = reverse('permissions-list')
        self.prerequisites = Prerequisites()

    fixtures = ['status', 'permissions']

    def setUp(self):
        self.prerequisites.superuser()

    def test_401(self):
        # get API response
        response = self.client.get(self.path, format='json')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_200(self):
        # authenticate
        self.prerequisites.auth(self.client)
        # get API response
        response = self.client.get(self.path, format='json')
        # get data from db
        query = Permissions.objects.all()
        serializer = PermissionsReadSerializer(query, many=True)
        self.assertEqual(response.data, serializer.data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)


############
# /roles/ #
############

# get
class GetRoles(APITestCase):
    def __init__(self, *args, **kwargs):
        super(GetRoles, self).__init__(*args, **kwargs)
        self.path = reverse('roles-list')
        self.prerequisites = Prerequisites()

    fixtures = ['status', 'roles']

    def setUp(self):
        self.prerequisites.superuser()

    def test_401(self):
        # get API response
        response = self.client.get(self.path, format='json')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    # test to verify that response includes csrf token
    def test_200_csrf(self):
        # authenticate
        self.prerequisites.auth(self.client)
        # get API response
        response = self.client.get(self.path, format='json')
        self.assertIsNotNone(self.prerequisites.verify_csrf(response))

    def test_200(self):
        # authenticate
        self.prerequisites.auth(self.client)
        # get API response
        response = self.client.get(self.path, format='json')
        # get data from db
        query = Roles.objects.all()
        serializer = RolesReadSerializer(query, many=True)
        self.assertEqual(response.data, serializer.data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)


# post
class PostRoles(APITestCase):
    def __init__(self, *args, **kwargs):
        super(PostRoles, self).__init__(*args, **kwargs)
        self.path = reverse('roles-list')
        self.prerequisites = Prerequisites(base_path=self.path)

    fixtures = ['status', 'permissions', 'roles']

    def setUp(self):
        self.client = APIClient(enforce_csrf_checks=True)
        self.prerequisites.superuser()
        self.valid_payload = {
            'role': 'test'
        }
        self.invalid_payload = {
            'role': ''
        }

    def test_401e(self):
        # get API response
        response = self.client.post(self.path, data=self.valid_payload, format='json')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_403_csrf(self):
        # authenticate
        self.prerequisites.auth(self.client)
        # get API response
        response = self.client.post(self.path, data=self.valid_payload, format='json')
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_400(self):
        # authenticate
        self.prerequisites.auth(self.client)
        # get csrf
        csrf_token = self.prerequisites.get_csrf(self.client)
        # get API response
        response = self.client.post(self.path, data=self.invalid_payload, format='json', HTTP_X_CSRFTOKEN=csrf_token)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_200(self):
        # authenticate
        self.prerequisites.auth(self.client)
        # get csrf
        csrf_token = self.prerequisites.get_csrf(self.client)
        # get API response
        response = self.client.post(self.path, data=self.valid_payload, format='json', HTTP_X_CSRFTOKEN=csrf_token)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data['version'], 1)
        self.assertEqual(response.data['status'], 'draft')


####################################
# /roles/{lifecycle_id}/{version}/ #
####################################

# get
class GetRolesLifecycleIdVersion(APITestCase):
    def __init__(self, *args, **kwargs):
        super(GetRolesLifecycleIdVersion, self).__init__(*args, **kwargs)
        self.base_path = reverse('roles-list')
        self.prerequisites = Prerequisites()

    fixtures = ['status', 'permissions', 'roles']

    def setUp(self):
        self.prerequisites.superuser()
        self.role_lifecycle = Roles.objects.filter(role='all').get().lifecycle_id
        self.role_version = 1
        self.path = '{}{}/{}'.format(self.base_path, self.role_lifecycle, self.role_version)

    def test_401(self):
        # get API response
        response = self.client.get(self.path, format='json')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_200_csrf(self):
        # authenticate
        self.prerequisites.auth(self.client)
        # get API response
        response = self.client.get(self.path, format='json')
        self.assertIsNotNone(self.prerequisites.verify_csrf(response))

    def test_200(self):
        # authenticate
        self.prerequisites.auth(self.client)
        # get API response
        response = self.client.get(self.path, format='json')
        # get data from db
        query = Roles.objects.get(lifecycle_id=self.role_lifecycle, version=self.role_version)
        serializer = RolesReadSerializer(query)
        self.assertEqual(response.data, serializer.data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_404_version(self):
        # authenticate
        self.prerequisites.auth(self.client)
        # get API response
        path = '{}{}/{}'.format(self.base_path, self.role_lifecycle, 2)
        response = self.client.get(path, format='json')
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_404_lifecycle(self):
        # authenticate
        self.prerequisites.auth(self.client)
        # get API response
        path = '{}{}/{}'.format(self.base_path, 'cac8d0f0-ce96-421c-9327-a44e4703d26f', self.role_version)
        response = self.client.get(path, format='json')
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)


# post
class PostRolesLifecycleIdVersion(APITestCase):
    """Test module for get all permissions"""
    def __init__(self, *args, **kwargs):
        super(PostRolesLifecycleIdVersion, self).__init__(*args, **kwargs)
        self.base_path = reverse('roles-list')
        self.prerequisites = Prerequisites(base_path=self.base_path)

    fixtures = ['status', 'permissions', 'roles']

    def setUp(self):
        self.client = APIClient(enforce_csrf_checks=True)
        self.prerequisites.superuser()
        self.role_lifecycle = Roles.objects.filter(role='all').get().lifecycle_id
        self.role_version = 1
        self.path = '{}{}/{}'.format(self.base_path, self.role_lifecycle, self.role_version)

        # role in draft for 400 new version
        self.role_draft_lifecycle = Roles.objects.create(role='draft', version=self.role_version,
                                                         status_id=Status.objects.draft).lifecycle_id
        # role in circulation for 400 new version
        self.role_circulation_lifecycle = Roles.objects.create(role='circulation', version=self.role_version,
                                                               status_id=Status.objects.circulation).lifecycle_id

    def test_401(self):
        # get API response
        response = self.client.post(self.path, format='json')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_403_csrf(self):
        # authenticate
        self.prerequisites.auth(self.client)
        # get API response
        response = self.client.post(self.path, format='json')
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_404_version(self):
        # authenticate
        self.prerequisites.auth(self.client)
        # get csrf
        csrf_token = self.prerequisites.get_csrf(self.client)
        # get API response
        path = '{}{}/{}'.format(self.base_path, self.role_lifecycle, 2)
        response = self.client.post(path, format='json', HTTP_X_CSRFTOKEN=csrf_token)
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_404_lifecycle(self):
        # authenticate
        self.prerequisites.auth(self.client)
        # get csrf
        csrf_token = self.prerequisites.get_csrf(self.client)
        # get API response
        path = '{}{}/{}'.format(self.base_path, 'cac8d0f0-ce96-421c-9327-a44e4703d26f', self.role_version)
        response = self.client.post(path, format='json', HTTP_X_CSRFTOKEN=csrf_token)
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_201(self):
        # authenticate
        self.prerequisites.auth(self.client)
        # get csrf
        csrf_token = self.prerequisites.get_csrf(self.client)
        # get API response
        response = self.client.post(self.path, format='json', HTTP_X_CSRFTOKEN=csrf_token)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data['version'], 2)
        self.assertEqual(response.data['lifecycle_id'], str(self.role_lifecycle))
        self.assertEqual(response.data['status'], 'draft')

    def test_400_second(self):
        # first add a new version
        self.test_201()
        # authenticate
        self.prerequisites.auth(self.client)
        # get csrf
        csrf_token = self.prerequisites.get_csrf(self.client)
        # second call for check that not a second version can be created
        response = self.client.post(self.path, format='json', HTTP_X_CSRFTOKEN=csrf_token)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_400_draft(self):
        # authenticate
        self.prerequisites.auth(self.client)
        # get csrf
        csrf_token = self.prerequisites.get_csrf(self.client)
        # get API response
        path = '{}{}/{}'.format(self.base_path, self.role_draft_lifecycle, self.role_version)
        response = self.client.post(path, format='json', HTTP_X_CSRFTOKEN=csrf_token)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_400_circulation(self):
        # authenticate
        self.prerequisites.auth(self.client)
        # get csrf
        csrf_token = self.prerequisites.get_csrf(self.client)
        # get API response
        path = '{}{}/{}'.format(self.base_path, self.role_circulation_lifecycle, self.role_version)
        response = self.client.post(path, format='json', HTTP_X_CSRFTOKEN=csrf_token)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


# delete
class DeleteRolesLifecycleIdVersion(APITestCase):
    """Test module for get all permissions"""
    def __init__(self, *args, **kwargs):
        super(DeleteRolesLifecycleIdVersion, self).__init__(*args, **kwargs)
        self.base_path = reverse('roles-list')
        self.prerequisites = Prerequisites(base_path=self.base_path)

    fixtures = ['status', 'permissions', 'roles']

    def setUp(self):
        self.client = APIClient(enforce_csrf_checks=True)
        self.prerequisites.superuser()
        self.role_lifecycle = Roles.objects.filter(role='all').get().lifecycle_id
        self.role_version = 1
        self.path = '{}{}/{}'.format(self.base_path, self.role_lifecycle, self.role_version)

        # role in draft for 400 delete
        self.role_400_status = []
        self.role_draft_lifecycle = Roles.objects.create(role='draft', version=self.role_version,
                                                         status_id=Status.objects.draft).lifecycle_id
        self.role_400_status.append(self.role_draft_lifecycle)
        self.role_400_status.append(self.role_lifecycle)
        # role in circulation for 400 delete
        self.role_400_status.append(Roles.objects.create(role='circulation', version=self.role_version,
                                                         status_id=Status.objects.circulation).lifecycle_id)
        # role in blocked for 400 delete
        self.role_400_status.append(Roles.objects.create(role='blocked', version=self.role_version,
                                                         status_id=Status.objects.blocked).lifecycle_id)
        # role in inactive for 400 delete
        self.role_400_status.append(Roles.objects.create(role='inactive', version=self.role_version,
                                                         status_id=Status.objects.inactive).lifecycle_id)
        # role in archived for 400 delete
        self.role_400_status.append(Roles.objects.create(role='archived', version=self.role_version,
                                                         status_id=Status.objects.archived).lifecycle_id)

    def test_401(self):
        # get API response
        response = self.client.delete(self.path, format='json')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_403_csrf(self):
        # authenticate
        self.prerequisites.auth(self.client)
        # get API response
        response = self.client.delete(self.path, format='json')
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_404_version(self):
        # authenticate
        self.prerequisites.auth(self.client)
        # get csrf
        csrf_token = self.prerequisites.get_csrf(self.client)
        # get API response
        path = '{}{}/{}'.format(self.base_path, self.role_lifecycle, 2)
        response = self.client.delete(path, format='json', HTTP_X_CSRFTOKEN=csrf_token)
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_404_lifecycle(self):
        # authenticate
        self.prerequisites.auth(self.client)
        # get csrf
        csrf_token = self.prerequisites.get_csrf(self.client)
        # get API response
        path = '{}{}/{}'.format(self.base_path, 'cac8d0f0-ce96-421c-9327-a44e4703d26f', self.role_version)
        response = self.client.delete(path, format='json', HTTP_X_CSRFTOKEN=csrf_token)
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_204(self):
        # authenticate
        self.prerequisites.auth(self.client)
        # get csrf
        csrf_token = self.prerequisites.get_csrf(self.client)
        # get API response
        path = '{}{}/{}'.format(self.base_path, self.role_draft_lifecycle, self.role_version)
        response = self.client.post(path, format='json', HTTP_X_CSRFTOKEN=csrf_token)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_400(self):
        # authenticate
        self.prerequisites.auth(self.client)
        # get csrf
        csrf_token = self.prerequisites.get_csrf(self.client)
        # get API response
        for role in self.role_400_status:
            path = '{}{}/{}'.format(self.base_path, role, self.role_version)
            response = self.client.post(path, format='json', HTTP_X_CSRFTOKEN=csrf_token)
            self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
