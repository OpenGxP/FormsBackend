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
from basics.models import Settings
from ..serializers import SettingsReadWriteSerializer

# test imports
from . import Prerequisites, GetAll, PatchOneNoStatus, GetOneNoStatus


BASE_PATH = reverse('settings-list')


##############
# /settings/ #
##############

# get
class GetAllSettings(GetAll):
    def __init__(self, *args, **kwargs):
        super(GetAllSettings, self).__init__(*args, **kwargs)
        self.base_path = BASE_PATH
        self.model = Settings
        self.serializer = SettingsReadWriteSerializer
        self.execute = True


class GetOneNoStatusSettings(GetOneNoStatus):
    def __init__(self, *args, **kwargs):
        super(GetOneNoStatusSettings, self).__init__(*args, **kwargs)
        self.base_path = BASE_PATH
        self.prerequisites = Prerequisites(base_path=self.base_path)
        self.model = Settings
        self.serializer = SettingsReadWriteSerializer
        self.execute = True
        self.data_available = True
        self.ok_object_data_unique = 'key'
        self.test_data = 'core.system_username'


# patch
class PatchOneSettings(PatchOneNoStatus):
    def __init__(self, *args, **kwargs):
        super(PatchOneSettings, self).__init__(*args, **kwargs)
        self.base_path = BASE_PATH
        self.model = Settings
        self.prerequisites = Prerequisites(base_path=self.base_path)
        self.serializer = SettingsReadWriteSerializer
        self.execute = True
        self.data_available = True
        self.ok_object_data_unique = 'key'
        self.test_data = 'core.system_username'
        self.valid_payload = {'value': 'testusername'}
        self.invalid_payload = {'key': 'changedkey'}


class SettingsMiscellaneous(APITestCase):
    """Test module for get all permissions"""
    def __init__(self, *args, **kwargs):
        super(SettingsMiscellaneous, self).__init__(*args, **kwargs)
        self.base_path = BASE_PATH
        self.prerequisites = Prerequisites(base_path=self.base_path)
        self.test_data_username = 'core.system_username'
        self.test_data_attempts = 'auth.max_login_attempts'
        self.test_data_logout = 'core.auto_logout'
        self.test_data_email = 'email.sender'

    def setUp(self):
        self.client = Client(enforce_csrf_checks=True)
        self.prerequisites.role_superuser()

    def test_405_delete(self):
        """
        This test shall how that is not possible to delete settings.
        """
        # authenticate
        self.prerequisites.auth(self.client)
        # get csrf
        csrf_token = self.prerequisites.get_csrf(self.client)
        # get API response
        path = '{}/{}'.format(self.base_path, self.test_data_username)
        response = self.client.delete(path, content_type='application/json',
                                      HTTP_X_CSRFTOKEN=csrf_token)
        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

    def test_405_post(self):
        """
        Test shall show that is not possible to add new settings.
        """
        # authenticate
        self.prerequisites.auth(self.client)
        # get csrf
        csrf_token = self.prerequisites.get_csrf(self.client)
        # get API response
        data = {
            'key': 'test',
            'default': 'defaultvalue',
            'value': 'testvalue'
        }
        response = self.client.post(self.base_path, data=data, content_type='application/json',
                                    HTTP_X_CSRFTOKEN=csrf_token)
        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

    def test_400_max_attempts(self):
        """
        Test shall show that is not possible to edit max login attempts to anything other than positive integers.
        """
        # authenticate
        self.prerequisites.auth(self.client)
        # get csrf
        csrf_token = self.prerequisites.get_csrf(self.client)
        # get API response
        path = '{}/{}'.format(self.base_path, self.test_data_attempts)
        data = {'value': 'test'}
        response = self.client.patch(path, data=data, content_type='application/json', HTTP_X_CSRFTOKEN=csrf_token)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        data = {'value': '0'}
        response = self.client.patch(path, data=data, content_type='application/json', HTTP_X_CSRFTOKEN=csrf_token)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_400_logout_interval(self):
        """
        Test shall show that is not possible to edit auto logout time lower than configured on backend.
        """
        # authenticate
        self.prerequisites.auth(self.client)
        # get csrf
        csrf_token = self.prerequisites.get_csrf(self.client)
        # get API response
        path = '{}/{}'.format(self.base_path, self.test_data_logout)
        data = {'value': '0.5'}
        response = self.client.patch(path, data=data, content_type='application/json', HTTP_X_CSRFTOKEN=csrf_token)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    # FO-177: added test ro verify that non-email formatted values are not allowed
    def test_400_email_format(self):
        """
        Test shall show that is not possible to add sender email with non-email format.
        """
        # authenticate
        self.prerequisites.auth(self.client)
        # get csrf
        csrf_token = self.prerequisites.get_csrf(self.client)
        # get API response
        path = '{}/{}'.format(self.base_path, self.test_data_email)
        data = {'value': 'testnoemail'}
        response = self.client.patch(path, data=data, content_type='application/json', HTTP_X_CSRFTOKEN=csrf_token)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_200_max_attempts(self):
        """
                Test shall show that is not possible to edit max login attempts to anything other than positive integers.
                """
        # authenticate
        self.prerequisites.auth(self.client)
        # get csrf
        csrf_token = self.prerequisites.get_csrf(self.client)
        # get API response
        path = '{}/{}'.format(self.base_path, self.test_data_attempts)
        data = {'value': '10'}
        response = self.client.patch(path, data=data, content_type='application/json', HTTP_X_CSRFTOKEN=csrf_token)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_200_auto_logout(self):
        """
                Test shall show that is not possible to edit max login attempts to anything other than positive integers.
                """
        # authenticate
        self.prerequisites.auth(self.client)
        # get csrf
        csrf_token = self.prerequisites.get_csrf(self.client)
        # get API response
        path = '{}/{}'.format(self.base_path, self.test_data_logout)
        data = {'value': '300'}
        response = self.client.patch(path, data=data, content_type='application/json', HTTP_X_CSRFTOKEN=csrf_token)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
