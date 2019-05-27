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
from ..models import Vault
from ..serializers import UsersPassword

# test imports
from . import GetAll, Prerequisites


#########################
# /admin/users_password #
#########################

# get
class GetVault(GetAll):
    def __init__(self, *args, **kwargs):
        super(GetVault, self).__init__(*args, **kwargs)
        self.base_path = reverse('users-password-list')
        self.model = Vault
        self.serializer = UsersPassword
        self.execute = True

    def test_200_csrf(self):
        pass


# patch
class ChangePassword(APITestCase):
    def __init__(self, *args, **kwargs):
        super(ChangePassword, self).__init__(*args, **kwargs)
        self.prerequisites = Prerequisites()
        self.base_path = reverse('change-password-view', args=[self.prerequisites.username])
        self.password = 'neutestdaidja2223213sdsd'

    def setUp(self):
        self.client = Client(enforce_csrf_checks=True)
        self.prerequisites.role_superuser()
        self.prerequisites.role_no_permissions()
        self.ok_path = self.base_path
        self.nok_path = reverse('change-password-view', args=['nonexistinguser'])
        self.ok_data = {'password': self.password,
                        'password_two': self.password}

    def test_401(self):
        # reset auth
        self.client.logout()
        # get API response
        response = self.client.patch(self.ok_path, content_type='application/json')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_403(self):
        # authenticate
        self.prerequisites.auth_no_perms(self.client)
        # get API response
        response = self.client.patch(self.ok_path, content_type='application/json')
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_403_csrf(self):
        # authenticate
        self.prerequisites.auth(self.client)
        # get API response
        response = self.client.patch(self.ok_path, data=self.ok_data, content_type='application/json')
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_404(self):
        # authenticate
        self.prerequisites.auth(self.client)
        # get csrf
        csrf_token = self.prerequisites.get_csrf(self.client, path=reverse('users-password-list'))
        # get API response
        response = self.client.patch(self.nok_path, data=self.ok_data, content_type='application/json',
                                     HTTP_X_CSRFTOKEN=csrf_token)
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_400(self):
        # authenticate
        self.prerequisites.auth(self.client)
        # get csrf
        csrf_token = self.prerequisites.get_csrf(self.client, reverse('users-password-list'))
        # get API response
        invalid_payload = [{'password': self.password},
                           {'password': self.password,
                            'password_two': 'abc'},
                           {'password': '1234',
                            'password_two': '1234'},
                           {'password': 'test',
                            'password_two': 'test'},
                           {'password_two': self.password}
                           ]
        for payload in invalid_payload:
            response = self.client.patch(self.ok_path, data=payload, content_type='application/json',
                                         HTTP_X_CSRFTOKEN=csrf_token)
            self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_200(self):
        # authenticate
        self.prerequisites.auth(self.client)
        # get csrf
        csrf_token = self.prerequisites.get_csrf(self.client, reverse('users-password-list'))
        # get API response
        response = self.client.patch(self.ok_path, data=self.ok_data, content_type='application/json',
                                     HTTP_X_CSRFTOKEN=csrf_token)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # try to log in with new password
        # reset auth
        self.client.logout()
        # get API response
        data = {'username': self.prerequisites.username, 'password': self.password}
        response = self.client.post(reverse('login-view'), data=data, content_type='application/json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
