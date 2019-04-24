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
from django.test import Client

# rest framework imports
from rest_framework import status
from rest_framework.test import APITestCase

# app imports
from ..models import Users, Roles, Status
from ..serializers import UsersReadSerializer

# test imports
from . import Prerequisites, GetAll, GetOne, PostNew, PostNewVersion, PatchOneStatus, DeleteOne, PatchOne


BASE_PATH = reverse('users-list')


###########
# /users/ #
###########

# get
class GetAllUsers(GetAll):
    def __init__(self, *args, **kwargs):
        super(GetAllUsers, self).__init__(*args, **kwargs)
        self.base_path = BASE_PATH
        self.model = Users
        self.serializer = UsersReadSerializer
        self.execute = True


# post
class PostNewUsers(PostNew):
    def __init__(self, *args, **kwargs):
        super(PostNewUsers, self).__init__(*args, **kwargs)
        self.base_path = BASE_PATH
        self.model = Users
        self.prerequisites = Prerequisites(base_path=self.base_path)
        self.valid_payload = {'username': 'testtest',
                              'password': 'test12345test',
                              'roles': 'all',
                              'valid_from': timezone.now(),
                              'ldap': False}
        self.invalid_payloads = [dict(),
                                 {'username': 'testtest',
                                  'roles': 'all',
                                  'password': '',
                                  'valid_from': timezone.now()},
                                 {'username': 'testtest',
                                  'password': 'test12345test',
                                  'roles': '',
                                  'valid_from': timezone.now()}]
        self.execute = True


####################################
# /users/{lifecycle_id}/{version}/ #
####################################

# get
class GetOneUser(GetOne):
    def __init__(self, *args, **kwargs):
        super(GetOneUser, self).__init__(*args, **kwargs)
        self.base_path = BASE_PATH
        self.model = Users
        self.prerequisites = Prerequisites(base_path=self.base_path)
        self.serializer = UsersReadSerializer
        self.ok_object_data = {'username': 'testtest',
                               'password': 'test12345test',
                               'roles': 'all',
                               'valid_from': timezone.now(),
                               'ldap': False}
        self.execute = True


# post
class PostNewVersionUser(PostNewVersion):
    def __init__(self, *args, **kwargs):
        super(PostNewVersionUser, self).__init__(*args, **kwargs)
        self.base_path = BASE_PATH
        self.model = Users
        self.prerequisites = Prerequisites(base_path=self.base_path)
        self.serializer = UsersReadSerializer
        self.ok_object_data = {'username': 'testtest',
                               'password': 'test12345test',
                               'roles': 'all',
                               'valid_from': timezone.now(),
                               'ldap': False}
        self.fail_object_draft_data = {'username': 'testtestzwei',
                                       'password': 'test12345test',
                                       'roles': 'all',
                                       'valid_from': timezone.now(),
                                       'ldap': False}
        self.fail_object_circulation_data = {'username': 'testtestdrei',
                                             'password': 'test12345test',
                                             'roles': 'all',
                                             'valid_from': timezone.now(),
                                             'ldap': False}
        self.execute = True


# delete
class DeleteOneUser(DeleteOne):
    def __init__(self, *args, **kwargs):
        super(DeleteOneUser, self).__init__(*args, **kwargs)
        self.base_path = BASE_PATH
        self.model = Users
        self.prerequisites = Prerequisites(base_path=self.base_path)
        self.serializer = UsersReadSerializer
        self.ok_object_data = {'username': 'testtest',
                               'password': 'test12345test',
                               'roles': 'all',
                               'valid_from': timezone.now(),
                               'ldap': False}
        self.execute = True


# patch
class PatchOneUser(PatchOne):
    def __init__(self, *args, **kwargs):
        super(PatchOneUser, self).__init__(*args, **kwargs)
        self.base_path = BASE_PATH
        self.model = Users
        self.prerequisites = Prerequisites(base_path=self.base_path)
        self.serializer = UsersReadSerializer
        self.ok_object_data = {'username': 'testtest',
                               'password': 'test12345test',
                               'roles': 'all',
                               'valid_from': timezone.now(),
                               'ldap': False}
        self.valid_payload = {'username': 'dasddasd',
                              'password': 'test12345test',
                              'roles': 'all',
                              'valid_from': timezone.now(),
                              'ldap': False}
        self.invalid_payload = {'username': '',
                                'password': 'test12345test',
                                'roles': 'all',
                                'valid_from': timezone.now(),
                                'ldap': False}
        self.unique_invalid_payload = self.ok_object_data = {'username': 'anders',
                                                             'password': 'test12345test',
                                                             'roles': 'all',
                                                             'valid_from': timezone.now(),
                                                             'ldap': False}
        self.execute = True


############################################
# /roles/{lifecycle_id}/{version}/{status} #
############################################

# patch
class PatchOneStatusUser(PatchOneStatus):
    def __init__(self, *args, **kwargs):
        super(PatchOneStatusUser, self).__init__(*args, **kwargs)
        self.base_path = BASE_PATH
        self.model = Users
        self.prerequisites = Prerequisites(base_path=self.base_path)
        self.serializer = UsersReadSerializer
        self.ok_object_data = {'username': 'testtest',
                               'password': 'test12345test',
                               'roles': 'all',
                               'valid_from': timezone.now(),
                               'ldap': False}
        self.execute = True


#################
# MISCELLANEOUS #
#################

class UsersMiscellaneous(APITestCase):
    def __init__(self, *args, **kwargs):
        super(UsersMiscellaneous, self).__init__(*args, **kwargs)
        self.base_path = BASE_PATH
        self.prerequisites = Prerequisites(base_path=self.base_path)
        self.ok_object_data = {'username': 'testtest',
                               'password': 'test12345test',
                               'roles': 'all',
                               'ldap': False}
        self.draft_role_id = 'newrole'
        self.draft_role = {
            'role': self.draft_role_id,
        }
        self.valid_payload = {'username': 'testtest',
                              'password': 'test12345test',
                              'roles': self.draft_role_id,
                              'ldap': False}
        self.valid_payload_two_roles = {'username': 'testtest',
                                        'password': 'test12345test',
                                        'roles': 'all,{}'.format(self.draft_role_id),
                                        'ldap': False}
        self.valid_payload_three = {'username': 'testtest',
                                    'password': 'test12345test',
                                    'roles': 'all',
                                    'ldap': False}

    def setUp(self):
        self.client = Client(enforce_csrf_checks=True)
        self.prerequisites.role_superuser()
        self.prerequisites.role_superuser_two()

    def test_400_non_prod_role(self):
        """
        Test shall show that users can not be set in circulation while their assigned role is no in status "productive".
        """
        # authenticate
        self.prerequisites.auth(self.client)
        # get csrf
        csrf_token = self.prerequisites.get_csrf(self.client)

        # add role in status draft
        path = reverse('roles-list')
        response_first = self.client.post(path, data=self.draft_role, content_type='application/json',
                                          HTTP_X_CSRFTOKEN=csrf_token)
        self.assertEqual(response_first.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response_first.data['version'], 1)
        self.assertEqual(response_first.data['status'], 'draft')

        # add user with not productive role
        response = self.client.post(self.base_path, data=self.valid_payload, content_type='application/json',
                                    HTTP_X_CSRFTOKEN=csrf_token)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data['version'], 1)
        self.assertEqual(response.data['status'], 'draft')

        # try to start circulation of user with role not in status productive
        path = '{}/{}/{}/{}'.format(self.base_path, response.data['lifecycle_id'], 1, 'circulation')
        response_circ = self.client.patch(path, content_type='application/json', HTTP_X_CSRFTOKEN=csrf_token)
        self.assertEqual(response_circ.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response_circ.data['validation_errors'][0], 'Role "{}" not in status productive.'
                         .format(self.draft_role_id))
        self.assertEqual(response.data['status'], 'draft')

    def test_400_one_non_prod_role(self):
        """
        Test shall show that users can not be set in circulation while their at least one of the assigned roles
        is no in status "productive".
        """
        # authenticate
        self.prerequisites.auth(self.client)
        # get csrf
        csrf_token = self.prerequisites.get_csrf(self.client)

        # add role in status draft
        path = reverse('roles-list')
        response_first = self.client.post(path, data=self.draft_role, content_type='application/json',
                                          HTTP_X_CSRFTOKEN=csrf_token)
        self.assertEqual(response_first.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response_first.data['version'], 1)
        self.assertEqual(response_first.data['status'], 'draft')

        # add user with one not productive role and one productive role (all)
        response = self.client.post(self.base_path, data=self.valid_payload_two_roles, content_type='application/json',
                                    HTTP_X_CSRFTOKEN=csrf_token)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data['version'], 1)
        self.assertEqual(response.data['status'], 'draft')

        # try to start circulation of user with one role not in status productive
        path = '{}/{}/{}/{}'.format(self.base_path, response.data['lifecycle_id'], 1, 'circulation')
        response_circ = self.client.patch(path, content_type='application/json', HTTP_X_CSRFTOKEN=csrf_token)
        self.assertEqual(response_circ.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response_circ.data['validation_errors'][0], 'Role "{}" not in status productive.'
                         .format(self.draft_role_id))

    def test_400_non_prod_after_circ(self):
        """
        Test shall show that user cannot be set productive with a role not in status "productive". Before setting in
        status "productive", the assigned role is blocked.
        """
        # authenticate
        self.prerequisites.auth(self.client)
        # get csrf
        csrf_token = self.prerequisites.get_csrf(self.client)

        # add user with productive role
        response = self.client.post(self.base_path, data=self.valid_payload_three, content_type='application/json',
                                    HTTP_X_CSRFTOKEN=csrf_token)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data['version'], 1)
        self.assertEqual(response.data['status'], 'draft')

        # start circulation of user with role in status productive
        path = '{}/{}/{}/{}'.format(self.base_path, response.data['lifecycle_id'], 1, 'circulation')
        response_circ = self.client.patch(path, content_type='application/json', HTTP_X_CSRFTOKEN=csrf_token)
        self.assertEqual(response_circ.status_code, status.HTTP_200_OK)
        self.assertEqual(response_circ.data['status'], 'circulation')

        # block all role
        query = Roles.objects.filter(role='all', status=Status.objects.productive).get()
        path = '{}/{}/{}/{}'.format(reverse('roles-list'), query.lifecycle_id, query.version, 'blocked')
        response_blocked = self.client.patch(path, content_type='application/json', HTTP_X_CSRFTOKEN=csrf_token)
        self.assertEqual(response_blocked.status_code, status.HTTP_200_OK)
        self.assertEqual(response_blocked.data['status'], 'blocked')

        # try to set user with assigned blocked role in status "productive"
        # auth with second user to avoid SoD
        self.prerequisites.auth_two(self.client)
        # get csrf
        csrf_token = self.prerequisites.get_csrf(self.client)
        path = '{}/{}/{}/{}'.format(self.base_path, response.data['lifecycle_id'], 1, 'productive')
        response_prod = self.client.patch(path, content_type='application/json', HTTP_X_CSRFTOKEN=csrf_token)
        self.assertEqual(response_prod.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response_prod.data['validation_errors'][0], 'Role "all" not in status productive.')
