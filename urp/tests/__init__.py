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
from ..models import Users, Status


class Prerequisites(object):
    def __init__(self, base_path=None):
        self.username = 'superuser'
        self.password = 'test1234'
        self.base_path = base_path
        # user for tests without permissions
        self.username_no_perm = 'usernoperms'
        # user for valid from tests
        self.username_valid_from = 'uservalidfrom'
        # user for read only permissions
        self.username_no_write_perm = 'usernowriteperms'

    def create_record(self, ext_client, data):
        # authenticate
        self.auth(ext_client)
        # get csrf
        csrf_token = self.get_csrf(ext_client)
        # get API response
        response = ext_client.post(self.base_path, data=data, format='json', HTTP_X_CSRFTOKEN=csrf_token)
        if response.status_code == status.HTTP_201_CREATED:
            return response.data
        else:
            raise AssertionError('Error Code: {}, Can not create prerequisite record.'
                                 .format(response.status_code))

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

    def role_no_write_permissions(self):
        role = 'no_write_perms'
        call_command('create-role', name=role, permissions='pe.rea,ro.rea,us.rea,st.rea')
        Users.objects.create_superuser(username=self.username_no_write_perm, password=self.password, role=role)

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

    def auth_no_write_perms(self, ext_client):
        data = {'username': self.username_no_write_perm, 'password': self.password}
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
        self.base_path = None
        self.model = None
        self.serializer = None

        # flag for execution
        self.execute = False

    def setUp(self):
        if self.execute:
            self.prerequisites.role_superuser()
            self.prerequisites.role_no_permissions()
            self.ok_path = self.base_path

    def test_401(self):
        if self.execute:
            # reset auth header
            self.client.credentials()
            # get API response
            response = self.client.get(self.ok_path, format='json')
            self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_403(self):
        if self.execute:
            # authenticate
            self.prerequisites.auth_no_perms(self.client)
            # get API response
            response = self.client.get(self.ok_path, format='json')
            self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    # test to verify that response includes csrf token
    def test_200_csrf(self):
        if self.execute:
            # authenticate
            self.prerequisites.auth(self.client)
            # get API response
            response = self.client.get(self.ok_path, format='json')
            self.assertIsNotNone(self.prerequisites.verify_csrf(response))

    def test_200(self):
        if self.execute:
            # authenticate
            self.prerequisites.auth(self.client)
            # get API response
            response = self.client.get(self.ok_path, format='json')
            # get data from db
            query = self.model.objects.all()
            serializer = self.serializer(query, many=True)
            self.assertEqual(response.data, serializer.data)
            self.assertEqual(response.status_code, status.HTTP_200_OK)


class GetOne(APITestCase):
    def __init__(self, *args, **kwargs):
        super(GetOne, self).__init__(*args, **kwargs)
        # placeholders
        self.base_path = None
        self.model = None
        self.prerequisites = None
        self.read_serializer = None
        self.write_serializer = None
        self.ok_object_data = None

        # flag for execution
        self.execute = False

    def setUp(self):
        if self.execute:
            self.prerequisites.role_superuser()
            self.prerequisites.role_no_permissions()
            # create ok object
            self.ok_object = self.prerequisites.create_record(self.client, self.ok_object_data)
            # create ok path
            self.ok_path = '{}{}/{}'.format(self.base_path, self.ok_object['lifecycle_id'], self.ok_object['version'])
            self.query = {'lifecycle_id': self.ok_object['lifecycle_id'],
                          'version': self.ok_object['version']}
            self.false_path_version = '{}{}/{}'.format(self.base_path, self.ok_object['lifecycle_id'], 2)
            self.false_path_uuid = '{}{}/{}'.format(self.base_path, 'cac8d0f0-ce96-421c-9327-a44e4703d26f',
                                                    self.ok_object['version'])
            self.false_path_both = '{}{}/{}'.format(self.base_path, 'cac8d0f0-ce96-421c-9327-a44e4703d26f', 2)

    def test_401(self):
        if self.execute:
            # reset auth header
            self.client.credentials()
            # get API response
            response = self.client.get(self.ok_path, format='json')
            self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_403(self):
        if self.execute:
            # authenticate
            self.prerequisites.auth_no_perms(self.client)
            # get API response
            response = self.client.get(self.ok_path, format='json')
            self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_200_csrf(self):
        if self.execute:
            # authenticate
            self.prerequisites.auth(self.client)
            # get API response
            response = self.client.get(self.ok_path, format='json')
            self.assertIsNotNone(self.prerequisites.verify_csrf(response))

    def test_200(self):
        if self.execute:
            # authenticate
            self.prerequisites.auth(self.client)
            # get API response
            response = self.client.get(self.ok_path, format='json')
            # get data from db
            query = self.model.objects.get(**self.query)
            serializer = self.read_serializer(query)
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
        self.base_path = None
        self.model = None
        self.prerequisites = None
        self.valid_payload = None
        self.invalid_payloads = None

        # flag for execution
        self.execute = False

    def setUp(self):
        if self.execute:
            self.client = APIClient(enforce_csrf_checks=True)
            self.prerequisites.role_superuser()
            self.prerequisites.role_no_write_permissions()
            self.ok_path = self.base_path

    def test_401(self):
        if self.execute:
            # reset auth header
            self.client.credentials()
            # get API response
            response = self.client.post(self.ok_path, data=self.valid_payload, format='json')
            self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_403_csrf(self):
        if self.execute:
            # authenticate
            self.prerequisites.auth(self.client)
            # get API response
            response = self.client.post(self.ok_path, data=self.valid_payload, format='json')
            self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_403_permission(self):
        if self.execute:
            # authenticate
            self.prerequisites.auth_no_write_perms(self.client)
            # get csrf
            csrf_token = self.prerequisites.get_csrf(self.client)
            # get API response
            response = self.client.post(self.ok_path, data=self.valid_payload, format='json',
                                        HTTP_X_CSRFTOKEN=csrf_token)
            self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_400(self):
        if self.execute:
            # authenticate
            self.prerequisites.auth(self.client)
            # get csrf
            csrf_token = self.prerequisites.get_csrf(self.client)
            # get API response
            for payload in self.invalid_payloads:
                response = self.client.post(self.ok_path, data=payload, format='json', HTTP_X_CSRFTOKEN=csrf_token)
                self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_201(self):
        if self.execute:
            # authenticate
            self.prerequisites.auth(self.client)
            # get csrf
            csrf_token = self.prerequisites.get_csrf(self.client)
            # get API response
            response = self.client.post(self.ok_path, data=self.valid_payload, format='json',
                                        HTTP_X_CSRFTOKEN=csrf_token)
            self.assertEqual(response.status_code, status.HTTP_201_CREATED)
            self.assertEqual(response.data['version'], 1)
            self.assertEqual(response.data['status'], 'draft')


# post
class PostNewVersion(APITestCase):
    def __init__(self, *args, **kwargs):
        super(PostNewVersion, self).__init__(*args, **kwargs)

        # placeholders
        self.base_path = None
        self.model = None
        self.read_serializer = None
        self.write_serializer = None
        self.ok_object_data = None
        self.fail_object_draft_data = None
        self.fail_object_circulation_data = None
        self.prerequisites = None

        # flag for execution
        self.execute = False

    def setUp(self):
        if self.execute:
            self.client = APIClient(enforce_csrf_checks=True)
            self.prerequisites.role_superuser()
            self.prerequisites.role_no_write_permissions()
            # create ok object in status draft
            self.ok_object = self.prerequisites.create_record(self.client, self.ok_object_data)
            # push ok object to ok status
            # authenticate
            self.prerequisites.auth(self.client)
            # get csrf
            csrf_token = self.prerequisites.get_csrf(self.client)
            path = '{}{}/{}/{}'.format(self.base_path, self.ok_object['lifecycle_id'], self.ok_object['version'],
                                       'circulation')
            self.client.patch(path, format='json', HTTP_X_CSRFTOKEN=csrf_token)
            path = '{}{}/{}/{}'.format(self.base_path, self.ok_object['lifecycle_id'], self.ok_object['version'],
                                       'productive')
            self.client.patch(path, format='json', HTTP_X_CSRFTOKEN=csrf_token)
            # create ok path
            self.ok_path = '{}{}/{}'.format(self.base_path, self.ok_object['lifecycle_id'], self.ok_object['version'])
            self.query = {'lifecycle_id': self.ok_object['lifecycle_id'],
                          'version': self.ok_object['version']}
            # create not ok paths
            self.false_path_version = '{}{}/{}'.format(self.base_path, self.ok_object['lifecycle_id'], 2)
            self.false_path_uuid = '{}{}/{}'.format(self.base_path, 'cac8d0f0-ce96-421c-9327-a44e4703d26f',
                                                    self.ok_object['version'])
            self.false_path_both = '{}{}/{}'.format(self.base_path, 'cac8d0f0-ce96-421c-9327-a44e4703d26f', 2)

            # create fail object draft
            self.fail_object_draft = self.prerequisites.create_record(self.client, self.fail_object_draft_data)
            self.fail_path_draft = '{}{}/{}'.format(self.base_path, self.fail_object_draft['lifecycle_id'],
                                                    self.fail_object_draft['version'])

            # create fail object circulation
            self.fail_object_circulation = self.prerequisites.create_record(self.client,
                                                                            self.fail_object_circulation_data)
            path = '{}{}/{}/{}'.format(self.base_path, self.fail_object_circulation['lifecycle_id'],
                                       self.fail_object_circulation['version'], 'circulation')
            self.client.patch(path, format='json', HTTP_X_CSRFTOKEN=csrf_token)
            self.fail_path_circulation = '{}{}/{}'.format(self.base_path, self.fail_object_circulation['lifecycle_id'],
                                                          self.fail_object_circulation['version'])

    def test_401(self):
        if self.execute:
            # reset auth header
            self.client.credentials()
            # get API response
            response = self.client.post(self.ok_path, format='json')
            self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_403_csrf(self):
        if self.execute:
            # authenticate
            self.prerequisites.auth(self.client)
            # get API response
            response = self.client.post(self.ok_path, format='json')
            self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_403_permission(self):
        if self.execute:
            # authenticate
            self.prerequisites.auth_no_write_perms(self.client)
            # get csrf
            csrf_token = self.prerequisites.get_csrf(self.client)
            # get API response
            response = self.client.post(self.ok_path, format='json', HTTP_X_CSRFTOKEN=csrf_token)
            self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_404_both(self):
        if self.execute:
            # authenticate
            self.prerequisites.auth(self.client)
            # get API response
            response = self.client.post(self.false_path_both, format='json')
            self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_404_version(self):
        if self.execute:
            # authenticate
            self.prerequisites.auth(self.client)
            # get API response
            response = self.client.post(self.false_path_version, format='json')
            self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_404_uuid(self):
        if self.execute:
            # authenticate
            self.prerequisites.auth(self.client)
            # get API response
            response = self.client.post(self.false_path_uuid, format='json')
            self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_201(self):
        if self.execute:
            # authenticate
            self.prerequisites.auth(self.client)
            # get csrf
            csrf_token = self.prerequisites.get_csrf(self.client)
            # get API response
            response = self.client.post(self.ok_path, format='json', HTTP_X_CSRFTOKEN=csrf_token)
            self.assertEqual(response.status_code, status.HTTP_201_CREATED)
            self.assertEqual(response.data['version'], 2)
            self.assertEqual(response.data['lifecycle_id'], str(self.ok_object['lifecycle_id']))
            self.assertEqual(response.data['status'], 'draft')
            # add check that data is the same, except status and version
            query = self.model.objects.get(**self.query)
            serializer = self.read_serializer(query)
            self.assertEqual(response.data[self.model.UNIQUE], serializer.data[self.model.UNIQUE])
            self.assertEqual(response.data['valid_from'], serializer.data['valid_from'])

    def test_400_second(self):
        if self.execute:
            # first add a new version
            self.test_201()
            # authenticate
            self.prerequisites.auth(self.client)
            # get csrf
            csrf_token = self.prerequisites.get_csrf(self.client)
            # second call for check that not a second version can be created
            response = self.client.post(self.ok_path, format='json', HTTP_X_CSRFTOKEN=csrf_token)
            self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_400_draft(self):
        if self.execute:
            # authenticate
            self.prerequisites.auth(self.client)
            # get csrf
            csrf_token = self.prerequisites.get_csrf(self.client)
            # get API response
            response = self.client.post(self.fail_path_draft, format='json', HTTP_X_CSRFTOKEN=csrf_token)
            self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_400_circulation(self):
        if self.execute:
            # authenticate
            self.prerequisites.auth(self.client)
            # get csrf
            csrf_token = self.prerequisites.get_csrf(self.client)
            # get API response
            response = self.client.post(self.fail_path_circulation, format='json', HTTP_X_CSRFTOKEN=csrf_token)
            self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
