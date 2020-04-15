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

# python imports
import time

# django imports
from django.urls import reverse
from django.utils import timezone
from django.test import Client
from rest_framework.serializers import ValidationError

# rest framework imports
from rest_framework.test import APITestCase
from rest_framework import status

# app imports
from ..models import Roles

# test imports
from . import Prerequisites


class Miscellaneous(APITestCase):
    def __init__(self, *args, **kwargs):
        super(Miscellaneous, self).__init__(*args, **kwargs)
        self.path = reverse('roles-list')
        self.prerequisites = Prerequisites(base_path=self.path)

    def setUp(self):
        self.client = Client(enforce_csrf_checks=True)
        self.prerequisites.role_superuser()
        self.prerequisites.role_superuser_two()
        self.prerequisites.role_past_valid_from()

    def test_403_invalid_range(self):
        # get data from db
        role = Roles.objects.filter(role='past_valid_from').get()
        # FO-228: because new validation rules, it is not possible to set role invalid in test scenario with public api
        # therefore, just change validity range via internal data model to make role invalid
        role.valid_from = timezone.now()
        role.valid_to = timezone.now()
        role.save()
        # try to authenticate with user who has invalid roles
        # FO-123: new test to verify that login with invalid role raises 400 error
        with self.assertRaises(ValidationError):
            self.prerequisites.auth_not_valid_roles(self.client)


# FO-228: new test case to verify validity range of status managed objects with the example roles.
# shall behave identical for all status managed objects
class ValidityRange(APITestCase):
    def __init__(self, *args, **kwargs):
        super(ValidityRange, self).__init__(*args, **kwargs)
        self.path = reverse('roles-list')
        self.prerequisites = Prerequisites(base_path=self.path)

    def setUp(self):
        self.client = Client(enforce_csrf_checks=True)
        self.prerequisites.role_superuser()
        self.prerequisites.role_superuser_two()

    def test_400_valid_from_circulation(self):
        """This test shall show that it is not possible to start circulation of a status managed record with
        valid from in the past."""
        # authenticate
        self.prerequisites.auth(self.client)
        # get csrf
        csrf_token = self.prerequisites.get_csrf(self.client)
        # get API response
        data = {'role': 'test',
                'valid_from': timezone.datetime(year=2000, month=6, day=1)}
        # create first record in status draft and version 1
        response = self.client.post(self.path, data=data, content_type='application/json',
                                    HTTP_X_CSRFTOKEN=csrf_token)
        # start circulation
        path = '{}/{}/{}/{}'.format(self.path, response.data['lifecycle_id'], 1, 'circulation')
        response_circ = self.client.patch(path, data={}, content_type='application/json', HTTP_X_CSRFTOKEN=csrf_token)
        self.assertEqual(response_circ.status_code, status.HTTP_400_BAD_REQUEST)

    def test_400_valid_to_circulation(self):
        """This test shall show that it is not possible to start circulation of a status managed record with
        valid to in the past."""
        # authenticate
        self.prerequisites.auth(self.client)
        # get csrf
        csrf_token = self.prerequisites.get_csrf(self.client)
        # get API response
        data = {'role': 'test',
                'valid_to': timezone.datetime(year=2000, month=6, day=1)}
        # create first record in status draft and version 1
        response = self.client.post(self.path, data=data, content_type='application/json',
                                    HTTP_X_CSRFTOKEN=csrf_token)
        # start circulation
        path = '{}/{}/{}/{}'.format(self.path, response.data['lifecycle_id'], 1, 'circulation')
        response_circ = self.client.patch(path, data={}, content_type='application/json', HTTP_X_CSRFTOKEN=csrf_token)
        self.assertEqual(response_circ.status_code, status.HTTP_400_BAD_REQUEST)

    def test_400_valid_from_to_circulation(self):
        """This test shall show that it is not possible to start circulation of a status managed record with
        valid from greater than valid to."""
        # authenticate
        self.prerequisites.auth(self.client)
        # get csrf
        csrf_token = self.prerequisites.get_csrf(self.client)
        # get API response
        data = {'role': 'test',
                'valid_from': timezone.datetime(year=2080, month=1, day=1),
                'valid_to': timezone.datetime(year=2079, month=1, day=1)}
        # create first record in status draft and version 1
        response = self.client.post(self.path, data=data, content_type='application/json',
                                    HTTP_X_CSRFTOKEN=csrf_token)
        # start circulation
        path = '{}/{}/{}/{}'.format(self.path, response.data['lifecycle_id'], 1, 'circulation')
        response_circ = self.client.patch(path, data={}, content_type='application/json', HTTP_X_CSRFTOKEN=csrf_token)
        self.assertEqual(response_circ.status_code, status.HTTP_400_BAD_REQUEST)

    def test_400_valid_from_productive(self):
        """This test shall show that it is not possible to set productive of a status managed record with
        valid from in the past."""
        # authenticate
        self.prerequisites.auth(self.client)
        # get csrf
        csrf_token = self.prerequisites.get_csrf(self.client)
        # get API response
        # create later record that it can be set in circulation
        now = timezone.now()
        later = now + timezone.timedelta(seconds=3)
        data = {'role': 'test',
                'valid_from': later}
        # create first record in status draft and version 1
        response = self.client.post(self.path, data=data, content_type='application/json',
                                    HTTP_X_CSRFTOKEN=csrf_token)
        # start circulation
        path = '{}/{}/{}/{}'.format(self.path, response.data['lifecycle_id'], 1, 'circulation')
        response_circ = self.client.patch(path, data={}, content_type='application/json', HTTP_X_CSRFTOKEN=csrf_token)
        self.assertEqual(response_circ.status_code, status.HTTP_200_OK)

        # wait 3 seconds that previous circulated valid from is in the past
        time.sleep(3)

        # auth with second user to avoid SoD
        self.prerequisites.auth_two(self.client)
        # get csrf
        csrf_token = self.prerequisites.get_csrf(self.client)
        path = '{}/{}/{}/{}'.format(self.path, response.data['lifecycle_id'], 1, 'productive')
        response_prod = self.client.patch(path, data={}, content_type='application/json', HTTP_X_CSRFTOKEN=csrf_token)
        self.assertEqual(response_prod.status_code, status.HTTP_400_BAD_REQUEST)

    def test_400_valid_to_productive(self):
        """This test shall show that it is not possible to set productive of a status managed record with
        valid to in the past."""
        # authenticate
        self.prerequisites.auth(self.client)
        # get csrf
        csrf_token = self.prerequisites.get_csrf(self.client)
        # get API response
        # create later record that it can be set in circulation
        now = timezone.now()
        later = now + timezone.timedelta(seconds=3)
        data = {'role': 'test',
                'valid_to': later}
        # create first record in status draft and version 1
        response = self.client.post(self.path, data=data, content_type='application/json',
                                    HTTP_X_CSRFTOKEN=csrf_token)
        # start circulation
        path = '{}/{}/{}/{}'.format(self.path, response.data['lifecycle_id'], 1, 'circulation')
        response_circ = self.client.patch(path, data={}, content_type='application/json', HTTP_X_CSRFTOKEN=csrf_token)
        self.assertEqual(response_circ.status_code, status.HTTP_200_OK)

        # wait 3 seconds that previous circulated valid to is in the past
        time.sleep(3)

        # auth with second user to avoid SoD
        self.prerequisites.auth_two(self.client)
        # get csrf
        csrf_token = self.prerequisites.get_csrf(self.client)
        path = '{}/{}/{}/{}'.format(self.path, response.data['lifecycle_id'], 1, 'productive')
        response_prod = self.client.patch(path, data={}, content_type='application/json', HTTP_X_CSRFTOKEN=csrf_token)
        self.assertEqual(response_prod.status_code, status.HTTP_400_BAD_REQUEST)
