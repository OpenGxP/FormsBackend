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

# django imports
from django.urls import reverse
from django.core.management import call_command

# rest framework imports
from rest_framework import status
from rest_framework.test import APIClient, APITestCase


# app imports
from ..models import Users


class Prerequisites(object):
    def __init__(self, base_path=None):
        self.username = 'superuser'
        self.password = 'test1234'
        self.base_path = base_path
        # user for tests without permissions
        self.username_no_perm = 'usernoperms'
        # user for valid from tests
        self.username_valid_from = 'uservalidfrom'

    @staticmethod
    def create_record(serializer, data):
        data['version'] = 1
        _serializer = serializer(data=data, context={'method': 'POST', 'function': 'new'})
        if _serializer.is_valid():
            _serializer.save()
        else:
            raise AssertionError('Can not create prerequisite record.')

    def role_superuser(self):
        call_command('initialize-status')
        call_command('collect-permissions')
        role = 'all'
        call_command('create-role', name=role)
        Users.objects.create_superuser(username=self.username, password=self.password, role=role)

    def role_no_permissions(self):
        role = 'no_perms'
        call_command('create-role', name=role, permissions='false,false')
        Users.objects.create_superuser(username=self.username_no_perm, password=self.password, role=role)

    def role_past_valid_from(self):
        role = 'past_valid_from'
        call_command('create-role', name=role, valid_from='01-01-2016 00:00:00')
        Users.objects.create_superuser(username=self.username_valid_from, password=self.password, role=role)

    def auth(self, ext_client):
        data = {'username': self.username, 'password': self.password}
        client = APIClient()
        response = client.post(path=reverse('token_obtain_pair'), data=data, format='json')
        ext_client.credentials(HTTP_AUTHORIZATION='Bearer ' + response.data['access'])

    def auth_no_perms(self, ext_client):
        data = {'username': self.username_no_perm, 'password': self.password}
        client = APIClient()
        response = client.post(path=reverse('token_obtain_pair'), data=data, format='json')
        ext_client.credentials(HTTP_AUTHORIZATION='Bearer ' + response.data['access'])

    def auth_not_valid_roles(self, ext_client):
        data = {'username': self.username_valid_from, 'password': self.password}
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


class GetAll(APITestCase):
    def __init__(self, *args, **kwargs):
        super(GetAll, self).__init__(*args, **kwargs)
        self.prerequisites = Prerequisites()

        # placeholders
        self.path = None
        self.model = None
        self.serializer = None

        # flag for execution
        self.execute = False

    def setUp(self):
        if self.execute:
            self.prerequisites.role_superuser()
            self.prerequisites.role_no_permissions()

    def test_401(self):
        if self.execute:
            # get API response
            response = self.client.get(self.path, format='json')
            self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_403(self):
        if self.execute:
            # authenticate
            self.prerequisites.auth_no_perms(self.client)
            # get API response
            response = self.client.get(self.path, format='json')
            self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    # test to verify that response includes csrf token
    def test_200_csrf(self):
        if self.execute:
            # authenticate
            self.prerequisites.auth(self.client)
            # get API response
            response = self.client.get(self.path, format='json')
            self.assertIsNotNone(self.prerequisites.verify_csrf(response))

    def test_200(self):
        if self.execute:
            # authenticate
            self.prerequisites.auth(self.client)
            # get API response
            response = self.client.get(self.path, format='json')
            # get data from db
            query = self.model.objects.all()
            serializer = self.serializer(query, many=True)
            self.assertEqual(response.data, serializer.data)
            self.assertEqual(response.status_code, status.HTTP_200_OK)


class GetOne(APITestCase):
    def __init__(self, *args, **kwargs):
        super(GetOne, self).__init__(*args, **kwargs)
        self.prerequisites = Prerequisites()

        # placeholders
        self.path = None
        self.model = None
        self.serializer = None
        # self.write_serializer = None
        self.query = None
        self.false_path_version = None
        self.false_path_uuid = None
        self.false_path_both = None

        # flag for execution
        self.execute = False

    def test_401(self):
        if self.execute:
            # get API response
            response = self.client.get(self.path, format='json')
            self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_403(self):
        if self.execute:
            # authenticate
            self.prerequisites.auth_no_perms(self.client)
            # get API response
            response = self.client.get(self.path, format='json')
            self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_200_csrf(self):
        if self.execute:
            # authenticate
            self.prerequisites.auth(self.client)
            # get API response
            response = self.client.get(self.path, format='json')
            self.assertIsNotNone(self.prerequisites.verify_csrf(response))

    def test_200(self):
        if self.execute:
            # authenticate
            self.prerequisites.auth(self.client)
            # get API response
            response = self.client.get(self.path, format='json')
            # get data from db
            query = self.model.objects.get(self.query)
            serializer = self.serializer(query)
            self.assertEqual(response.data, serializer.data)
            self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_404_both(self):
        if self.execute:
            # authenticate
            self.prerequisites.auth(self.client)
            # get API response
            response = self.client.get(self.false_path_both, format='json')
            self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_404_version(self):
        if self.execute:
            # authenticate
            self.prerequisites.auth(self.client)
            # get API response
            response = self.client.get(self.false_path_version, format='json')
            self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_404_uuid(self):
        if self.execute:
            # authenticate
            self.prerequisites.auth(self.client)
            # get API response
            response = self.client.get(self.false_path_uuid, format='json')
            self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)


# post
class PostNew(APITestCase):
    def __init__(self, *args, **kwargs):
        super(PostNew, self).__init__(*args, **kwargs)

        # placeholders
        self.path = None
        self.model = None
        self.serializer = None
        self.prerequisites = None

        # flag for execution
        self.execute = False

    def setUp(self):
        if self.execute:
            self.client = APIClient(enforce_csrf_checks=True)
            self.prerequisites.role_superuser()

            # placeholders
            self.valid_payload = None
            self.invalid_payloads = None

    def test_401(self):
        if self.execute:
            # get API response
            response = self.client.post(self.path, data=self.valid_payload, format='json')
            self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_403_csrf(self):
        if self.execute:
            # authenticate
            self.prerequisites.auth(self.client)
            # get API response
            response = self.client.post(self.path, data=self.valid_payload, format='json')
            self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_400(self):
        if self.execute:
            # authenticate
            self.prerequisites.auth(self.client)
            # get csrf
            csrf_token = self.prerequisites.get_csrf(self.client)
            # get API response
            for payload in self.invalid_payloads:
                response = self.client.post(self.path, data=payload, format='json', HTTP_X_CSRFTOKEN=csrf_token)
                self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_201(self):
        if self.execute:
            # authenticate
            self.prerequisites.auth(self.client)
            # get csrf
            csrf_token = self.prerequisites.get_csrf(self.client)
            # get API response
            response = self.client.post(self.path, data=self.valid_payload, format='json', HTTP_X_CSRFTOKEN=csrf_token)
            self.assertEqual(response.status_code, status.HTTP_201_CREATED)
            self.assertEqual(response.data['version'], 1)
            self.assertEqual(response.data['status'], 'draft')
