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
from urp.models.profile import Profile
from urp.serializers.profile import ProfileReadWriteSerializer

# test imports
from . import Prerequisites, GetAll, PatchOneNoStatus, GetOneNoStatus


BASE_PATH = reverse('profile-list')


#############
# /profile/ #
#############

# get
class GetAllProfiles(GetAll):
    def __init__(self, *args, **kwargs):
        super(GetAllProfiles, self).__init__(*args, **kwargs)
        self.base_path = BASE_PATH
        self.model = Profile
        self.serializer = ProfileReadWriteSerializer
        self.execute = True
        self.perm_required = False
        self.filter = {'username': self.prerequisites.username}


class GetOneNoStatusProfile(GetOneNoStatus):
    def __init__(self, *args, **kwargs):
        super(GetOneNoStatusProfile, self).__init__(*args, **kwargs)
        self.base_path = BASE_PATH
        self.prerequisites = Prerequisites(base_path=self.base_path)
        self.model = Profile
        self.serializer = ProfileReadWriteSerializer
        self.execute = True
        self.perm_required = False
        self.data_available = True
        self.filter = {'username': self.prerequisites.username}
        self.ok_object_data_unique = 'key'
        self.test_data = 'loc.timezone'


# patch
class PatchOneProfile(PatchOneNoStatus):
    def __init__(self, *args, **kwargs):
        super(PatchOneProfile, self).__init__(*args, **kwargs)
        self.base_path = BASE_PATH
        self.model = Profile
        self.prerequisites = Prerequisites(base_path=self.base_path)
        self.serializer = ProfileReadWriteSerializer
        self.execute = True
        self.perm_required = False
        self.data_available = True
        self.ok_object_data_unique = 'key'
        self.test_data = 'loc.language'
        self.valid_payload = {'value': 'de_DE'}
        self.invalid_payload = {'key': 'changedkey'}
        self.filter = {'username': self.prerequisites.username}


class ProfileMiscellaneous(APITestCase):
    def __init__(self, *args, **kwargs):
        super(ProfileMiscellaneous, self).__init__(*args, **kwargs)
        self.base_path = BASE_PATH
        self.prerequisites = Prerequisites(base_path=self.base_path)
        self.test_data_timezone = 'loc.timezone'
        self.test_data_language = 'loc.language'

    def setUp(self):
        self.client = Client(enforce_csrf_checks=True)
        self.prerequisites.role_superuser()

    def test_405_delete(self):
        """
        This test shall how that is not possible to delete profile records.
        """
        # authenticate
        self.prerequisites.auth(self.client)
        # get csrf
        csrf_token = self.prerequisites.get_csrf(self.client)
        # get API response
        path = '{}/{}'.format(self.base_path, self.test_data_timezone)
        response = self.client.delete(path, content_type='application/json',
                                      HTTP_X_CSRFTOKEN=csrf_token)
        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

    def test_405_post(self):
        """
        Test shall show that is not possible to add new profile records.
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

    def test_400_timezone(self):
        """
        Test shall show that false timezones are not allowed.
        """
        # authenticate
        self.prerequisites.auth(self.client)
        # get csrf
        csrf_token = self.prerequisites.get_csrf(self.client)
        # get API response
        path = '{}/{}'.format(self.base_path, self.test_data_timezone)
        data = {'value': 'test'}
        response = self.client.patch(path, data=data, content_type='application/json', HTTP_X_CSRFTOKEN=csrf_token)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        data = {'value': '0'}
        response = self.client.patch(path, data=data, content_type='application/json', HTTP_X_CSRFTOKEN=csrf_token)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_400_initial_timezone(self):
        """
        Test shall show that false timezones are not allowed at initial set.
        """
        # authenticate
        self.prerequisites.auth(self.client)
        # get csrf
        csrf_token = self.prerequisites.get_csrf(self.client)
        # get API response
        path = '/user/set_timezone'
        data = {'value': 'test'}
        response = self.client.patch(path, data=data, content_type='application/json', HTTP_X_CSRFTOKEN=csrf_token)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        data = {'value': '0'}
        response = self.client.patch(path, data=data, content_type='application/json', HTTP_X_CSRFTOKEN=csrf_token)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_400_language(self):
        """
        Test shall show that false languages are not allowed.
        """
        # authenticate
        self.prerequisites.auth(self.client)
        # get csrf
        csrf_token = self.prerequisites.get_csrf(self.client)
        # get API response
        path = '{}/{}'.format(self.base_path, self.test_data_language)
        data = {'value': 'test'}
        response = self.client.patch(path, data=data, content_type='application/json', HTTP_X_CSRFTOKEN=csrf_token)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_200_timezone(self):
        """
        Test shall show that timezones can be changed to valid ones.
        """
        # authenticate
        self.prerequisites.auth(self.client)
        # get csrf
        csrf_token = self.prerequisites.get_csrf(self.client)
        # get API response
        path = '{}/{}'.format(self.base_path, self.test_data_timezone)
        data = {'value': 'Europe/Berlin'}
        response = self.client.patch(path, data=data, content_type='application/json', HTTP_X_CSRFTOKEN=csrf_token)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_200_initial_timezone(self):
        """
        Test shall show that timezones can be changed to valid ones at initial set.
        """
        # authenticate
        self.prerequisites.auth(self.client)
        # get csrf
        csrf_token = self.prerequisites.get_csrf(self.client)
        # get API response
        path = '/user/set_timezone'
        data = {'value': 'Europe/Berlin'}
        response = self.client.patch(path, data=data, content_type='application/json', HTTP_X_CSRFTOKEN=csrf_token)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_200_language(self):
        """
        Test shall show that language can be changed to valid values.
        """
        # authenticate
        self.prerequisites.auth(self.client)
        # get csrf
        csrf_token = self.prerequisites.get_csrf(self.client)
        # get API response
        path = '{}/{}'.format(self.base_path, self.test_data_language)
        data = {'value': 'de_DE'}
        response = self.client.patch(path, data=data, content_type='application/json', HTTP_X_CSRFTOKEN=csrf_token)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_overall_initial_timezone(self):
        """
        Test shall show that after initial log in, the timezone is not yet set. after set the initial flag is false.
        """
        # initial login
        data = {'username': self.prerequisites.username, 'password': self.prerequisites.password}
        response = self.client.post('/login', data=data, content_type='application/json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['initial_timezone'], True)

        # authenticate
        self.prerequisites.auth(self.client)
        # get csrf
        csrf_token = self.prerequisites.get_csrf(self.client)
        # get API response
        path = '/user/set_timezone'
        data = {'value': 'Europe/Vienna'}
        response = self.client.patch(path, data=data, content_type='application/json', HTTP_X_CSRFTOKEN=csrf_token)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # logout
        self.client.logout()

        # login after changing timezone
        data = {'username': self.prerequisites.username, 'password': self.prerequisites.password}
        response = self.client.post('/login', data=data, content_type='application/json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['initial_timezone'], False)
