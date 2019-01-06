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
from ..models import Roles

# test imports
from . import Prerequisites


class Miscellaneous(APITestCase):
    def __init__(self, *args, **kwargs):
        super(Miscellaneous, self).__init__(*args, **kwargs)
        self.path = reverse('roles-list')
        self.prerequisites = Prerequisites(base_path=self.path)
        self.valid_payload = {
            'role': 'past_valid_from',
            'valid_from': timezone.datetime.strptime('01-01-2017 00:00:00', '%d-%m-%Y %H:%M:%S'),
            'valid_to': timezone.datetime.strptime('01-01-2018 00:00:00', '%d-%m-%Y %H:%M:%S')
        }

    def setUp(self):
        self.client = APIClient(enforce_csrf_checks=True)
        self.prerequisites.role_superuser()
        self.prerequisites.role_past_valid_from()

    def test_403_invalid_range(self):
        # authenticate
        self.prerequisites.auth(self.client)
        # get csrf
        csrf_token = self.prerequisites.get_csrf(self.client)
        # get data from db
        role = Roles.objects.filter(role='past_valid_from').get()
        # create new version
        path = '{}{}/{}'.format(self.path, role.lifecycle_id, role.version)
        self.client.post(path, format='json', HTTP_X_CSRFTOKEN=csrf_token)
        # update draft version 2
        path = '{}{}/{}'.format(self.path, role.lifecycle_id, role.version + 1)
        self.client.patch(path, data=self.valid_payload, format='json', HTTP_X_CSRFTOKEN=csrf_token)
        # start circulation
        path = '{}{}/{}/{}'.format(self.path, role.lifecycle_id, role.version + 1, 'circulation')
        self.client.patch(path, data={}, format='json', HTTP_X_CSRFTOKEN=csrf_token)
        # set productive
        path = '{}{}/{}/{}'.format(self.path, role.lifecycle_id, role.version + 1, 'productive')
        self.client.patch(path, data={}, format='json', HTTP_X_CSRFTOKEN=csrf_token)
        # authenticate with user who has invalid roles
        self.prerequisites.auth_not_valid_roles(self.client)
        # get API response
        path = reverse('status-list')
        response = self.client.get(path, format='json')
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
