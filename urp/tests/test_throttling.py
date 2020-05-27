"""
opengxp.org
Copyright (C) 2020 Henrik Baran

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
from time import sleep

# django imports
from django.urls import reverse
from django.test import Client

# rest framework imports
from rest_framework import status
from rest_framework.test import APITestCase

# app imports
from . import Prerequisites


class AnonRateThrottle(APITestCase):
    def __init__(self, *args, **kwargs):
        super(AnonRateThrottle, self).__init__(*args, **kwargs)
        self.prerequisites = Prerequisites()
        self.path = reverse('login-view')

    def setUp(self):
        self.client = Client()
        self.prerequisites.role_superuser()

    def test_429_throttling(self):
        data = {'username': self.prerequisites.username, 'password': self.prerequisites.password}
        for x in range(100):
            # get API response
            response = self.client.post(self.path, data=data, content_type='application/json')
            self.assertEqual(response.status_code, status.HTTP_200_OK)
            self.client.logout()
            sleep(0.5)

        # try to login exceeding throttle limit
        response = self.client.post(self.path, data=data, content_type='application/json')
        self.assertEqual(response.status_code, status.HTTP_429_TOO_MANY_REQUESTS)
