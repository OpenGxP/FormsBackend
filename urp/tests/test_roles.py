"""
opengxp.org
Copyright (C) 2019 Henrik Baran

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
from django.utils import timezone

# rest framework imports
from rest_framework import status
from rest_framework.test import APITestCase, APIClient

# app imports
from ..models import Status, Roles
from ..serializers import RolesReadSerializer, RolesWriteSerializer

# test imports
from . import Prerequisites, GetAll, PostNew, GetOne, PostNewVersion, DeleteOne, PatchOne, PatchOneStatus


############
# /roles/ #
############

# get
class GetAllRoles(GetAll):
    def __init__(self, *args, **kwargs):
        super(GetAllRoles, self).__init__(*args, **kwargs)
        self.base_path = reverse('roles-list')
        self.model = Roles
        self.serializer = RolesReadSerializer
        self.execute = True


# post
class PostNewRoles(PostNew):
    def __init__(self, *args, **kwargs):
        super(PostNewRoles, self).__init__(*args, **kwargs)
        self.base_path = reverse('roles-list')
        self.model = Roles
        self.prerequisites = Prerequisites(base_path=self.base_path)
        self.valid_payload = {'role': 'test',
                              'valid_from': timezone.now()}
        self.invalid_payloads = [dict(),
                                 {'role': ''},
                                 {'role': 'test'}]
        self.execute = True


####################################
# /roles/{lifecycle_id}/{version}/ #
####################################

# get
class GetOneRole(GetOne):
    def __init__(self, *args, **kwargs):
        super(GetOneRole, self).__init__(*args, **kwargs)
        self.base_path = reverse('roles-list')
        self.model = Roles
        self.prerequisites = Prerequisites(base_path=self.base_path)
        self.serializer = RolesReadSerializer
        self.ok_object_data = {'role': 'test',
                               'valid_from': timezone.now()}
        self.execute = True


# post
class PostNewVersionRole(PostNewVersion):
    def __init__(self, *args, **kwargs):
        super(PostNewVersionRole, self).__init__(*args, **kwargs)
        self.base_path = reverse('roles-list')
        self.model = Roles
        self.prerequisites = Prerequisites(base_path=self.base_path)
        self.serializer = RolesReadSerializer
        self.ok_object_data = {'role': 'test',
                               'valid_from': timezone.now()}
        self.fail_object_draft_data = {'role': 'test_draft',
                                       'valid_from': timezone.now()}
        self.fail_object_circulation_data = {'role': 'test_circ',
                                             'valid_from': timezone.now()}
        self.execute = True


# delete
class DeleteOneRole(DeleteOne):
    def __init__(self, *args, **kwargs):
        super(DeleteOneRole, self).__init__(*args, **kwargs)
        self.base_path = reverse('roles-list')
        self.model = Roles
        self.prerequisites = Prerequisites(base_path=self.base_path)
        self.serializer = RolesReadSerializer
        self.ok_object_data = {'role': 'test',
                               'valid_from': timezone.now()}
        self.execute = True


# patch
class PatchOneRole(PatchOne):
    def __init__(self, *args, **kwargs):
        super(PatchOneRole, self).__init__(*args, **kwargs)
        self.base_path = reverse('roles-list')
        self.model = Roles
        self.prerequisites = Prerequisites(base_path=self.base_path)
        self.serializer = RolesReadSerializer
        self.ok_object_data = {'role': 'test',
                               'valid_from': timezone.now()}
        self.valid_payload = {
            'role': 'new_role',
            'valid_from': timezone.now()
        }
        self.invalid_payload = {
            'role': ''
        }
        self.execute = True


############################################
# /roles/{lifecycle_id}/{version}/{status} #
############################################

# patch
class PatchOneStatusRole(PatchOneStatus):
    def __init__(self, *args, **kwargs):
        super(PatchOneStatusRole, self).__init__(*args, **kwargs)
        self.base_path = reverse('roles-list')
        self.model = Roles
        self.prerequisites = Prerequisites(base_path=self.base_path)
        self.serializer = RolesReadSerializer
        self.ok_object_data = {'role': 'test',
                               'valid_from': timezone.now()}
        self.execute = True


# patch
class RolesMiscellaneous(APITestCase):
    """Test module for get all permissions"""
    def __init__(self, *args, **kwargs):
        super(RolesMiscellaneous, self).__init__(*args, **kwargs)
        self.base_path = reverse('roles-list')
        self.prerequisites = Prerequisites(base_path=self.base_path)
        now = timezone.now()
        later = now + timezone.timedelta(days=15)
        self.valid_payload = {
            'role': 'test',
            'valid_from': now
        }

        self.valid_payload_later = {
            'role': 'test',
            'valid_from': later
        }

        self.valid_payload_overlapping = {
            'role': 'test',
            'valid_from': timezone.datetime(year=2017, month=6, day=1),
        }

        self.invalid_payload = {
            'role': 'test',
            'valid_from': timezone.datetime(year=2018, month=1, day=1)
        }

        self.valid_payload_valid_to = {
            'role': 'test',
            'valid_from': timezone.datetime(year=2017, month=1, day=1),
            'valid_to': timezone.datetime(year=2018, month=1, day=1)
        }

    def setUp(self):
        self.client = APIClient(enforce_csrf_checks=True)
        self.prerequisites.role_superuser()

    def test_life_cycle(self):
        # authenticate
        self.prerequisites.auth(self.client)
        # get csrf
        csrf_token = self.prerequisites.get_csrf(self.client)
        # get API response
        # create first record in status draft and version 1
        path = self.base_path
        response_first = self.client.post(path, data=self.valid_payload, format='json', HTTP_X_CSRFTOKEN=csrf_token)
        self.assertEqual(response_first.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response_first.data['version'], 1)
        self.assertEqual(response_first.data['status'], 'draft')

        # create second record in status draft and version 1
        response_second = self.client.post(path, data=self.valid_payload, format='json', HTTP_X_CSRFTOKEN=csrf_token)
        self.assertEqual(response_second.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response_second.data['version'], 1)
        self.assertEqual(response_second.data['status'], 'draft')

        # start circulation of first record
        _status = 'circulation'
        path = '{}{}/{}/{}'.format(self.base_path, response_first.data['lifecycle_id'], 1, _status)
        response_first_circ = self.client.patch(path, data=self.valid_payload, format='json',
                                                HTTP_X_CSRFTOKEN=csrf_token)
        query = Roles.objects.filter(lifecycle_id=response_first.data['lifecycle_id'], version=1).get()
        serializer = RolesReadSerializer(query)
        self.assertEqual(response_first_circ.status_code, status.HTTP_200_OK)
        self.assertEqual(response_first_circ.data, serializer.data)
        self.assertEqual(response_first_circ.data['status'], _status)

        # try start circulation of second record
        _status = 'circulation'
        path = '{}{}/{}/{}'.format(self.base_path, response_second.data['lifecycle_id'], 1, _status)
        response_second_circ = self.client.patch(path, data=self.valid_payload, format='json',
                                                 HTTP_X_CSRFTOKEN=csrf_token)
        query = Roles.objects.filter(lifecycle_id=response_second.data['lifecycle_id'], version=1).get()
        serializer = RolesReadSerializer(query)
        self.assertEqual(response_second_circ.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(serializer.data['status'], 'draft')

        # push first record to productive
        _status = 'productive'
        path = '{}{}/{}/{}'.format(self.base_path, response_first.data['lifecycle_id'], 1, _status)
        response_first_prod = self.client.patch(path, data=self.valid_payload, format='json',
                                                HTTP_X_CSRFTOKEN=csrf_token)
        query = Roles.objects.filter(lifecycle_id=response_first.data['lifecycle_id'], version=1).get()
        serializer = RolesReadSerializer(query)
        self.assertEqual(response_first_prod.status_code, status.HTTP_200_OK)
        self.assertEqual(response_first_prod.data, serializer.data)
        self.assertEqual(response_first_prod.data['status'], _status)

        # try again to start circulation of second record
        _status = 'circulation'
        path = '{}{}/{}/{}'.format(self.base_path, response_second.data['lifecycle_id'], 1, _status)
        response_second_circ = self.client.patch(path, data=self.valid_payload, format='json',
                                                 HTTP_X_CSRFTOKEN=csrf_token)
        query = Roles.objects.filter(lifecycle_id=response_second.data['lifecycle_id'], version=1).get()
        serializer = RolesReadSerializer(query)
        self.assertEqual(response_second_circ.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(serializer.data['status'], 'draft')

        # create new version of first record
        path = '{}{}/{}'.format(self.base_path, response_first.data['lifecycle_id'], 1)
        response_first_two = self.client.post(path, format='json', HTTP_X_CSRFTOKEN=csrf_token)
        self.assertEqual(response_first_two.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response_first_two.data['version'], 2)
        self.assertEqual(response_first_two.data['lifecycle_id'], str(response_first.data['lifecycle_id']))
        self.assertEqual(response_first_two.data['status'], 'draft')

        # try again to # try again to start circulation of second record
        _status = 'circulation'
        path = '{}{}/{}/{}'.format(self.base_path, response_second.data['lifecycle_id'], 1, _status)
        response_second_circ = self.client.patch(path, data=self.valid_payload, format='json',
                                                 HTTP_X_CSRFTOKEN=csrf_token)
        query = Roles.objects.filter(lifecycle_id=response_second.data['lifecycle_id'], version=1).get()
        serializer = RolesReadSerializer(query)
        self.assertEqual(response_second_circ.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(serializer.data['status'], 'draft')

        # start circulation of first record
        _status = 'circulation'
        path = '{}{}/{}/{}'.format(self.base_path, response_first.data['lifecycle_id'], 2, _status)
        response_first_two_circ = self.client.patch(path, data=self.valid_payload, format='json',
                                                    HTTP_X_CSRFTOKEN=csrf_token)
        query = Roles.objects.filter(lifecycle_id=response_first.data['lifecycle_id'], version=2).get()
        serializer = RolesReadSerializer(query)
        self.assertEqual(response_first_two_circ.status_code, status.HTTP_200_OK)
        self.assertEqual(response_first_two_circ.data, serializer.data)
        self.assertEqual(response_first_two_circ.data['status'], _status)

        # try again to start circulation of second record
        _status = 'circulation'
        path = '{}{}/{}/{}'.format(self.base_path, response_second.data['lifecycle_id'], 1, _status)
        response_second_circ = self.client.patch(path, data=self.valid_payload, format='json',
                                                 HTTP_X_CSRFTOKEN=csrf_token)
        query = Roles.objects.filter(lifecycle_id=response_second.data['lifecycle_id'], version=1).get()
        serializer = RolesReadSerializer(query)
        self.assertEqual(response_second_circ.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(serializer.data['status'], 'draft')

    def test_version_one_updated_time(self):
        # authenticate
        self.prerequisites.auth(self.client)
        # get csrf
        csrf_token = self.prerequisites.get_csrf(self.client)
        # get API response
        # create first record in status draft and version 1
        path = self.base_path
        response = self.client.post(path, data=self.valid_payload_valid_to, format='json', HTTP_X_CSRFTOKEN=csrf_token)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data['version'], 1)
        self.assertEqual(response.data['status'], 'draft')

        # start circulation
        _status = 'circulation'
        path = '{}{}/{}/{}'.format(self.base_path, response.data['lifecycle_id'], 1, _status)
        response_circ = self.client.patch(path, data={}, format='json', HTTP_X_CSRFTOKEN=csrf_token)
        query = Roles.objects.filter(lifecycle_id=response.data['lifecycle_id'], version=1).get()
        serializer = RolesReadSerializer(query)
        self.assertEqual(response_circ.status_code, status.HTTP_200_OK)
        self.assertEqual(response_circ.data, serializer.data)
        self.assertEqual(response_circ.data['status'], _status)

        # push to productive
        _status = 'productive'
        path = '{}{}/{}/{}'.format(self.base_path, response.data['lifecycle_id'], 1, _status)
        response_prod = self.client.patch(path, data={}, format='json', HTTP_X_CSRFTOKEN=csrf_token)
        query = Roles.objects.filter(lifecycle_id=response.data['lifecycle_id'], version=1).get()
        serializer = RolesReadSerializer(query)
        self.assertEqual(response_prod.status_code, status.HTTP_200_OK)
        self.assertEqual(response_prod.data, serializer.data)
        self.assertEqual(response_prod.data['status'], _status)

        # create new version 2
        path = '{}{}/{}'.format(self.base_path, response.data['lifecycle_id'], 1)
        response_two = self.client.post(path, format='json', HTTP_X_CSRFTOKEN=csrf_token)
        self.assertEqual(response_two.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response_two.data['version'], 2)
        self.assertEqual(response_two.data['lifecycle_id'], str(response.data['lifecycle_id']))
        self.assertEqual(response_two.data['status'], 'draft')

        # update version 2 to a valid "valid from" after "valid from" and
        # before "valid_to" of previous version 1
        path = '{}{}/{}'.format(self.base_path, response.data['lifecycle_id'], 2)
        response = self.client.patch(path, data=self.valid_payload_overlapping, format='json',
                                     HTTP_X_CSRFTOKEN=csrf_token)
        query = Roles.objects.filter(lifecycle_id=response.data['lifecycle_id'], version=2).get()
        serializer = RolesReadSerializer(query)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data, serializer.data)

        # start circulation of version 2
        _status = 'circulation'
        path = '{}{}/{}/{}'.format(self.base_path, response.data['lifecycle_id'], 2, _status)
        response_circ = self.client.patch(path, data={}, format='json', HTTP_X_CSRFTOKEN=csrf_token)
        query = Roles.objects.filter(lifecycle_id=response.data['lifecycle_id'], version=2).get()
        serializer = RolesReadSerializer(query)
        self.assertEqual(response_circ.status_code, status.HTTP_200_OK)
        self.assertEqual(response_circ.data, serializer.data)
        self.assertEqual(response_circ.data['status'], _status)

        # push to productive of version 2
        _status = 'productive'
        path = '{}{}/{}/{}'.format(self.base_path, response.data['lifecycle_id'], 2, _status)
        response_prod = self.client.patch(path, data={}, format='json', HTTP_X_CSRFTOKEN=csrf_token)
        query = Roles.objects.filter(lifecycle_id=response.data['lifecycle_id'], version=2).get()
        serializer = RolesReadSerializer(query)
        self.assertEqual(response_prod.status_code, status.HTTP_200_OK)
        self.assertEqual(response_prod.data, serializer.data)
        self.assertEqual(response_prod.data['status'], _status)
        # new check to verify that version 1 "valid_to" is now "valid_from" of version 2
        query = Roles.objects.filter(lifecycle_id=response.data['lifecycle_id'], version=1).get()
        serializer = RolesReadSerializer(query)
        self.assertEqual(response_prod.data['valid_from'], serializer.data['valid_to'])

    def test_version_one_updated_None(self):
        # authenticate
        self.prerequisites.auth(self.client)
        # get csrf
        csrf_token = self.prerequisites.get_csrf(self.client)
        # get API response
        # create first record in status draft and version 1
        path = self.base_path
        response = self.client.post(path, data=self.valid_payload, format='json', HTTP_X_CSRFTOKEN=csrf_token)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data['version'], 1)
        self.assertEqual(response.data['status'], 'draft')

        # start circulation
        _status = 'circulation'
        path = '{}{}/{}/{}'.format(self.base_path, response.data['lifecycle_id'], 1, _status)
        response_circ = self.client.patch(path, data=self.valid_payload, format='json', HTTP_X_CSRFTOKEN=csrf_token)
        query = Roles.objects.filter(lifecycle_id=response.data['lifecycle_id'], version=1).get()
        serializer = RolesReadSerializer(query)
        self.assertEqual(response_circ.status_code, status.HTTP_200_OK)
        self.assertEqual(response_circ.data, serializer.data)
        self.assertEqual(response_circ.data['status'], _status)

        # push to productive
        _status = 'productive'
        path = '{}{}/{}/{}'.format(self.base_path, response.data['lifecycle_id'], 1, _status)
        response_prod = self.client.patch(path, data=self.valid_payload, format='json', HTTP_X_CSRFTOKEN=csrf_token)
        query = Roles.objects.filter(lifecycle_id=response.data['lifecycle_id'], version=1).get()
        serializer = RolesReadSerializer(query)
        self.assertEqual(response_prod.status_code, status.HTTP_200_OK)
        self.assertEqual(response_prod.data, serializer.data)
        self.assertEqual(response_prod.data['status'], _status)

        # create new version 2
        path = '{}{}/{}'.format(self.base_path, response.data['lifecycle_id'], 1)
        response_two = self.client.post(path, format='json', HTTP_X_CSRFTOKEN=csrf_token)
        self.assertEqual(response_two.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response_two.data['version'], 2)
        self.assertEqual(response_two.data['lifecycle_id'], str(response.data['lifecycle_id']))
        self.assertEqual(response_two.data['status'], 'draft')

        # change the valid from to a date before valid from of last version
        path = '{}{}/{}'.format(self.base_path, response.data['lifecycle_id'], 2)
        response = self.client.patch(path, data=self.invalid_payload, format='json', HTTP_X_CSRFTOKEN=csrf_token)
        query = Roles.objects.filter(lifecycle_id=response.data['lifecycle_id'], version=2).get()
        serializer = RolesReadSerializer(query)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data, serializer.data)

        # start circulation of version 2
        _status = 'circulation'
        path = '{}{}/{}/{}'.format(self.base_path, response.data['lifecycle_id'], 2, _status)
        response_circ = self.client.patch(path, data=self.valid_payload, format='json', HTTP_X_CSRFTOKEN=csrf_token)
        query = Roles.objects.filter(lifecycle_id=response.data['lifecycle_id'], version=2).get()
        serializer_before = RolesReadSerializer(query)
        # check if response if a bad request
        self.assertEqual(response_circ.status_code, status.HTTP_400_BAD_REQUEST)
        # verify that data remains un-altered
        self.assertEqual(serializer.data, serializer_before.data)

        # update version 2 again to a valid "valid from" after "valid from" of previous version 1
        path = '{}{}/{}'.format(self.base_path, response.data['lifecycle_id'], 2)
        response = self.client.patch(path, data=self.valid_payload_later, format='json', HTTP_X_CSRFTOKEN=csrf_token)
        query = Roles.objects.filter(lifecycle_id=response.data['lifecycle_id'], version=2).get()
        serializer = RolesReadSerializer(query)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data, serializer.data)

        # start circulation of version 2
        _status = 'circulation'
        path = '{}{}/{}/{}'.format(self.base_path, response.data['lifecycle_id'], 2, _status)
        response_circ = self.client.patch(path, data=self.valid_payload, format='json', HTTP_X_CSRFTOKEN=csrf_token)
        query = Roles.objects.filter(lifecycle_id=response.data['lifecycle_id'], version=2).get()
        serializer = RolesReadSerializer(query)
        self.assertEqual(response_circ.status_code, status.HTTP_200_OK)
        self.assertEqual(response_circ.data, serializer.data)
        self.assertEqual(response_circ.data['status'], _status)

        # push to productive of version 2
        _status = 'productive'
        path = '{}{}/{}/{}'.format(self.base_path, response.data['lifecycle_id'], 2, _status)
        response_prod = self.client.patch(path, data=self.valid_payload, format='json', HTTP_X_CSRFTOKEN=csrf_token)
        query = Roles.objects.filter(lifecycle_id=response.data['lifecycle_id'], version=2).get()
        serializer = RolesReadSerializer(query)
        self.assertEqual(response_prod.status_code, status.HTTP_200_OK)
        self.assertEqual(response_prod.data, serializer.data)
        self.assertEqual(response_prod.data['status'], _status)
        # new check to verify that version 1 "valid_to" is now "valid_from" of version 2
        query = Roles.objects.filter(lifecycle_id=response.data['lifecycle_id'], version=1).get()
        serializer = RolesReadSerializer(query)
        self.assertEqual(response_prod.data['valid_from'], serializer.data['valid_to'])

    def test_version_one_unaltered(self):
        # authenticate
        self.prerequisites.auth(self.client)
        # get csrf
        csrf_token = self.prerequisites.get_csrf(self.client)
        # get API response
        # create first record in status draft and version 1
        path = self.base_path
        response = self.client.post(path, data=self.valid_payload_valid_to, format='json', HTTP_X_CSRFTOKEN=csrf_token)

        # start circulation
        path = '{}{}/{}/{}'.format(self.base_path, response.data['lifecycle_id'], 1, 'circulation')
        self.client.patch(path, data={}, format='json', HTTP_X_CSRFTOKEN=csrf_token)

        # push to productive
        path = '{}{}/{}/{}'.format(self.base_path, response.data['lifecycle_id'], 1, 'productive')
        self.client.patch(path, data={}, format='json', HTTP_X_CSRFTOKEN=csrf_token)
        query = Roles.objects.filter(lifecycle_id=response.data['lifecycle_id'], version=1).get()
        serializer = RolesReadSerializer(query)
        old_valid_to = serializer.data['valid_to']

        # create new version 2
        path = '{}{}/{}'.format(self.base_path, response.data['lifecycle_id'], 1)
        self.client.post(path, format='json', HTTP_X_CSRFTOKEN=csrf_token)

        # change the valid from to a date after the valid_to of the previous version
        path = '{}{}/{}'.format(self.base_path, response.data['lifecycle_id'], 2)
        data = {'role': 'test',
                'valid_from': timezone.datetime(year=2019, month=1, day=1)}
        self.client.patch(path, data=data, format='json', HTTP_X_CSRFTOKEN=csrf_token)

        # start circulation of version 2
        path = '{}{}/{}/{}'.format(self.base_path, response.data['lifecycle_id'], 2, 'circulation')
        response_circ = self.client.patch(path, data={}, format='json', HTTP_X_CSRFTOKEN=csrf_token)
        query = Roles.objects.filter(lifecycle_id=response.data['lifecycle_id'], version=2).get()
        serializer = RolesReadSerializer(query)
        # should be ok
        self.assertEqual(response_circ.status_code, status.HTTP_200_OK)
        self.assertEqual(response_circ.data, serializer.data)

        # push to productive of version 2
        _status = 'productive'
        path = '{}{}/{}/{}'.format(self.base_path, response.data['lifecycle_id'], 2, _status)
        response_prod = self.client.patch(path, data={}, format='json', HTTP_X_CSRFTOKEN=csrf_token)
        query = Roles.objects.filter(lifecycle_id=response.data['lifecycle_id'], version=2).get()
        serializer = RolesReadSerializer(query)
        self.assertEqual(response_prod.status_code, status.HTTP_200_OK)
        self.assertEqual(response_prod.data, serializer.data)
        self.assertEqual(response_prod.data['status'], _status)

        # new check to verify that version 1 "valid_to" remains unaltered
        query = Roles.objects.filter(lifecycle_id=response.data['lifecycle_id'], version=1).get()
        serializer = RolesReadSerializer(query)
        self.assertEqual(old_valid_to, serializer.data['valid_to'])
