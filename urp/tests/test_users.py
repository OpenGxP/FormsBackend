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
from django.test import Client

# rest framework imports
from rest_framework import status
from rest_framework.test import APITestCase

# app imports
from urp.models import Users
from urp.serializers.users import UsersReadWriteSerializer

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
        self.serializer = UsersReadWriteSerializer
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
                              'password_verification': 'test12345test',
                              'roles': ['all'],
                              'email': 'example@example.com',
                              'ldap': False}
        self.invalid_payloads = [dict(),
                                 {'username': 'testtest',
                                  'roles': ['all'],
                                  'password': '',
                                  'email': 'example@example.com'},
                                 {'username': 'testtest',
                                  'password': 'test12345test',
                                  'roles': '',
                                  'email': 'example@example.com'},
                                 {'username': 'testtest',
                                  'password': 'test12345test',
                                  'roles': [],
                                  'email': 'example@example.com'},
                                 ]
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
        self.serializer = UsersReadWriteSerializer
        self.ok_object_data = {'username': 'testtest',
                               'password': 'test12345test',
                               'password_verification': 'test12345test',
                               'roles': ['all'],
                               'email': 'example@example.com',
                               'ldap': False}
        self.execute = True


# post
class PostNewVersionUser(PostNewVersion):
    def __init__(self, *args, **kwargs):
        super(PostNewVersionUser, self).__init__(*args, **kwargs)
        self.base_path = BASE_PATH
        self.model = Users
        self.prerequisites = Prerequisites(base_path=self.base_path)
        self.serializer = UsersReadWriteSerializer
        self.ok_object_data = {'username': 'testtest',
                               'password': 'test12345test',
                               'password_verification': 'test12345test',
                               'roles': ['all'],
                               'email': 'example@example.com',
                               'ldap': False}
        self.fail_object_draft_data = {'username': 'testtestzwei',
                                       'password': 'test12345test',
                                       'password_verification': 'test12345test',
                                       'roles': ['all'],
                                       'email': 'exampletwo@example.com',
                                       'ldap': False}
        self.fail_object_circulation_data = {'username': 'testtestdrei',
                                             'password': 'test12345test',
                                             'password_verification': 'test12345test',
                                             'roles': ['all'],
                                             'email': 'examplethree@example.com',
                                             'ldap': False}
        self.execute = True


# delete
class DeleteOneUser(DeleteOne):
    def __init__(self, *args, **kwargs):
        super(DeleteOneUser, self).__init__(*args, **kwargs)
        self.base_path = BASE_PATH
        self.model = Users
        self.prerequisites = Prerequisites(base_path=self.base_path)
        self.serializer = UsersReadWriteSerializer
        self.ok_object_data = {'username': 'testtest',
                               'password': 'test12345test',
                               'password_verification': 'test12345test',
                               'roles': ['all'],
                               'email': 'example@example.com',
                               'ldap': False}
        self.execute = True


# patch
class PatchOneUser(PatchOne):
    def __init__(self, *args, **kwargs):
        super(PatchOneUser, self).__init__(*args, **kwargs)
        self.base_path = BASE_PATH
        self.model = Users
        self.prerequisites = Prerequisites(base_path=self.base_path)
        self.serializer = UsersReadWriteSerializer
        self.ok_object_data = {'username': 'testtest',
                               'password': 'test12345test',
                               'password_verification': 'test12345test',
                               'roles': ['all'],
                               'email': 'example@example.com',
                               'ldap': False}
        self.valid_payload = {'username': 'testtest',
                              'roles': ['all_two'],
                              'email': 'example@example.com',
                              'ldap': False}
        self.invalid_payload = {'username': '',
                                'password': 'test12345test',
                                'roles': ['all'],
                                'email': 'example@example.com',
                                'ldap': False}
        self.unique_invalid_payload = {'username': 'anders',
                                       'roles': ['all'],
                                       'email': 'example@example.com',
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
        self.serializer = UsersReadWriteSerializer
        self.ok_object_data = {'username': 'testtest',
                               'password': 'test12345test',
                               'password_verification': 'test12345test',
                               'roles': ['all'],
                               'email': 'example@example.com',
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
        self.username = 'testtest'
        self.password = 'asdad2qa3dad2'
        self.ok_object_data = {'username': self.username,
                               'password': self.password,
                               'password_verification': self.password,
                               'roles': ['all'],
                               'ldap': False,
                               'email': 'example@example.com'}
        self.draft_role_id = 'newrole'
        self.draft_role = {
            'role': self.draft_role_id,
        }
        self.valid_payload = {'username': 'testtest',
                              'password': 'test12345test',
                              'password_verification': 'test12345test',
                              'roles': [self.draft_role_id],
                              'ldap': False,
                              'email': 'example@example.com'}
        self.valid_payload_two_roles = {'username': 'testtest',
                                        'password': 'test12345test',
                                        'password_verification': 'test12345test',
                                        'roles': ['all,{}'.format(self.draft_role_id)],
                                        'ldap': False,
                                        'email': 'example@example.com'}
        self.valid_payload_three = {'username': 'testtest',
                                    'password': 'test12345test',
                                    'password_verification': 'test12345test',
                                    'roles': ['all'],
                                    'ldap': False,
                                    'email': 'example@example.com'}

    def setUp(self):
        self.client = Client(enforce_csrf_checks=True)
        self.prerequisites.role_superuser()
        self.prerequisites.role_superuser_two()

    # FO-132: test for hash password at adding
    def test_200_new(self):
        """
        This test shall verify that a new added non-ldap managed user can login and its password is stored secure.
        """
        # authenticate
        self.prerequisites.auth(self.client)
        # get csrf
        csrf_token = self.prerequisites.get_csrf(self.client)

        # add new non-ldap managed user
        response = self.client.post(self.base_path, data=self.ok_object_data, content_type='application/json',
                                    HTTP_X_CSRFTOKEN=csrf_token)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        # start circulation
        path = '{}/{}/{}/{}'.format(self.base_path, response.data['lifecycle_id'], 1, 'circulation')
        response_circ = self.client.patch(path, content_type='application/json', HTTP_X_CSRFTOKEN=csrf_token)
        self.assertEqual(response_circ.status_code, status.HTTP_200_OK)

        # auth with second user to avoid SoD
        self.prerequisites.auth_two(self.client)
        # get csrf
        csrf_token = self.prerequisites.get_csrf(self.client)
        # set prod
        path = '{}/{}/{}/{}'.format(self.base_path, response.data['lifecycle_id'], 1, 'productive')
        response_prod = self.client.patch(path, content_type='application/json', HTTP_X_CSRFTOKEN=csrf_token)
        self.assertEqual(response_prod.status_code, status.HTTP_200_OK)
        # verify if password was stored secure
        query = Users.objects.filter(lifecycle_id=response.data['lifecycle_id']).get()
        self.assertTrue(query.check_password(self.password))

        # login with new user
        self.client.logout()
        response = self.client.login(username=self.username, password=self.password)
        self.assertTrue(response)

    def test_400_edit_version_two(self):
        """
        This test shall show that it is not possible to change the password using regular edit function for users in
        version 2 or higher.
        """
        # authenticate
        self.prerequisites.auth(self.client)
        # get csrf
        csrf_token = self.prerequisites.get_csrf(self.client)

        # add new non-ldap managed user
        response = self.client.post(self.base_path, data=self.ok_object_data, content_type='application/json',
                                    HTTP_X_CSRFTOKEN=csrf_token)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        # start circulation
        path = '{}/{}/{}/{}'.format(self.base_path, response.data['lifecycle_id'], 1, 'circulation')
        response_circ = self.client.patch(path, content_type='application/json', HTTP_X_CSRFTOKEN=csrf_token)
        self.assertEqual(response_circ.status_code, status.HTTP_200_OK)

        # auth with second user to avoid SoD
        self.prerequisites.auth_two(self.client)
        # get csrf
        csrf_token = self.prerequisites.get_csrf(self.client)
        # set prod
        path = '{}/{}/{}/{}'.format(self.base_path, response.data['lifecycle_id'], 1, 'productive')
        response_prod = self.client.patch(path, content_type='application/json', HTTP_X_CSRFTOKEN=csrf_token)
        self.assertEqual(response_prod.status_code, status.HTTP_200_OK)

        # try to update user password
        new_password = '32hai82dhaks8da'
        data = {'username': self.username,
                'password': new_password,
                'roles': 'all',
                'ldap': False,
                'email': 'example@example.com'}
        path = '{}/{}/{}'.format(self.base_path, response.data['lifecycle_id'], 1)
        response_update = self.client.patch(path, data=data, content_type='application/json',
                                            HTTP_X_CSRFTOKEN=csrf_token)
        self.assertEqual(response_update.status_code, status.HTTP_400_BAD_REQUEST)

    # FO-132: test for hash password during edit
    def test_200_edit(self):
        """
        This test shall verify that an updated non-ldap managed user can login and its password is stored secure.
        """
        # authenticate
        self.prerequisites.auth(self.client)
        # get csrf
        csrf_token = self.prerequisites.get_csrf(self.client)

        # add new non-ldap managed user
        response = self.client.post(self.base_path, data=self.ok_object_data, content_type='application/json',
                                    HTTP_X_CSRFTOKEN=csrf_token)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        # update draft record before validation
        new_password = '32hai82dhaks8da'
        data = {'username': self.username,
                'password': new_password,
                'password_two': new_password,
                'roles': ['all'],
                'ldap': False,
                'email': 'example@example.com'}
        path = '{}/{}/{}'.format(self.base_path, response.data['lifecycle_id'], 1)
        response_update = self.client.patch(path, data=data, content_type='application/json',
                                            HTTP_X_CSRFTOKEN=csrf_token)
        self.assertEqual(response_update.status_code, status.HTTP_200_OK)
        # verify if password was stored secure
        query = Users.objects.filter(lifecycle_id=response.data['lifecycle_id']).get()
        self.assertTrue(query.check_password(new_password))

        # start circulation
        path = '{}/{}/{}/{}'.format(self.base_path, response.data['lifecycle_id'], 1, 'circulation')
        response_circ = self.client.patch(path, content_type='application/json', HTTP_X_CSRFTOKEN=csrf_token)
        self.assertEqual(response_circ.status_code, status.HTTP_200_OK)

        # auth with second user to avoid SoD
        self.prerequisites.auth_two(self.client)
        # get csrf
        csrf_token = self.prerequisites.get_csrf(self.client)
        # set prod
        path = '{}/{}/{}/{}'.format(self.base_path, response.data['lifecycle_id'], 1, 'productive')
        response_prod = self.client.patch(path, content_type='application/json', HTTP_X_CSRFTOKEN=csrf_token)
        self.assertEqual(response_prod.status_code, status.HTTP_200_OK)

        # login with new user
        self.client.logout()
        response = self.client.login(username=self.username, password=new_password)
        self.assertTrue(response)
