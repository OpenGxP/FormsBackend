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
from rest_framework.serializers import ValidationError

# rest framework imports
from rest_framework.test import APITestCase

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
        self.client = Client(enforce_csrf_checks=True)
        self.prerequisites.role_superuser()
        self.prerequisites.role_superuser_two()
        self.prerequisites.role_past_valid_from()

    def test_403_invalid_range(self):
        # authenticate
        self.prerequisites.auth(self.client)
        # get csrf
        csrf_token = self.prerequisites.get_csrf(self.client)
        # get data from db
        role = Roles.objects.filter(role='past_valid_from').get()
        # create new version
        path = '{}/{}/{}'.format(self.path, role.lifecycle_id, role.version)
        self.client.post(path, content_type='application/json', HTTP_X_CSRFTOKEN=csrf_token)
        # update draft version 2
        path = '{}/{}/{}'.format(self.path, role.lifecycle_id, role.version + 1)
        self.client.patch(path, data=self.valid_payload, content_type='application/json', HTTP_X_CSRFTOKEN=csrf_token)
        # start circulation
        path = '{}/{}/{}/{}'.format(self.path, role.lifecycle_id, role.version + 1, 'circulation')
        self.client.patch(path, content_type='application/json', HTTP_X_CSRFTOKEN=csrf_token)
        # auth with second user to avoid SoD
        self.prerequisites.auth_two(self.client)
        # get csrf
        csrf_token = self.prerequisites.get_csrf(self.client)
        # set productive
        path = '{}/{}/{}/{}'.format(self.path, role.lifecycle_id, role.version + 1, 'productive')
        self.client.patch(path, content_type='application/json', HTTP_X_CSRFTOKEN=csrf_token)
        # try to authenticate with user who has invalid roles
        # FO-123: new test to verify that login with invalid role raises 400 error
        with self.assertRaises(ValidationError):
            self.prerequisites.auth_not_valid_roles(self.client)
