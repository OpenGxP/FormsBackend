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
from django.conf import settings

# rest framework imports
from rest_framework import status
from rest_framework.test import APITestCase

# app imports
from . import Prerequisites
from ..models import AccessLog, Users
from basics.models import Status


class Authenticate(APITestCase):
    def __init__(self, *args, **kwargs):
        super(Authenticate, self).__init__(*args, **kwargs)
        self.prerequisites = Prerequisites()
        self.path = reverse('token_obtain_pair')

    def setUp(self):
        self.prerequisites.role_superuser()

    def test_400_both(self):
        # get API response
        data = {'username': 'asdasdasd', 'password': 'sadasdasd'}
        response = self.client.post(self.path, data=data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_400_username(self):
        # get API response
        data = {'username': 'asdasdasd', 'password': self.prerequisites.password}
        response = self.client.post(self.path, data=data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_400_password(self):
        # get API response
        data = {'username': self.prerequisites.username, 'password': 'sadasdasd'}
        response = self.client.post(self.path, data=data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_200(self):
        # get API response
        data = {'username': self.prerequisites.username, 'password': self.prerequisites.password}
        response = self.client.post(self.path, data=data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)


class AuthenticateLogging(APITestCase):
    def __init__(self, *args, **kwargs):
        super(AuthenticateLogging, self).__init__(*args, **kwargs)
        self.prerequisites = Prerequisites()
        self.path = reverse('token_obtain_pair')
        self.access_log = AccessLog

    def setUp(self):
        self.prerequisites.role_superuser()

    def login_ok(self):
        # get API response
        data = {'username': self.prerequisites.username, 'password': self.prerequisites.password}
        self.client.post(self.path, data=data, format='json')
        query = AccessLog.objects.all()[0]
        self.assertEqual(query.username, self.prerequisites.username)
        self.assertEqual(query.action, 'login')
        self.assertEqual(query.attempt, 1)
        self.assertEqual(query.active, '--')

    def login_attempt(self):
        # get API response
        data = {'username': self.prerequisites.username, 'password': 'sadasdasd'}
        self.client.post(self.path, data=data, format='json')
        query = AccessLog.objects.all()[0]
        self.assertEqual(query.username, self.prerequisites.username)
        self.assertEqual(query.action, 'attempt')
        self.assertEqual(query.attempt, 1)
        self.assertEqual(query.active, 'yes')

    def login_attempt_max_allowed(self):
        # get API response
        data = {'username': self.prerequisites.username, 'password': 'sadasdasd'}
        # login for the maximum allowed attempts
        for idx in range(settings.MAX_LOGIN_ATTEMPTS):
            self.client.post(self.path, data=data, format='json')
        query = AccessLog.objects.all()
        for idx, record in enumerate(query):
            self.assertEqual(record.username, self.prerequisites.username)
            self.assertEqual(record.action, 'attempt')
            self.assertEqual(record.attempt, idx + 1)
            self.assertEqual(record.active, 'yes')

    def login_attempt_block(self):
        # get API response
        data = {'username': self.prerequisites.username, 'password': 'sadasdasd'}
        # login for the maximum allowed attempts
        for idx in range(settings.MAX_LOGIN_ATTEMPTS + 1):
            self.client.post(self.path, data=data, format='json')
        query = AccessLog.objects.all()
        for idx, record in enumerate(query):
            self.assertEqual(record.username, self.prerequisites.username)
            self.assertEqual(record.action, 'attempt')
            self.assertEqual(record.attempt, idx + 1)
            if idx + 1 > settings.MAX_LOGIN_ATTEMPTS:
                self.assertEqual(record.active, 'no')
                user = Users.objects.filter(username=self.prerequisites.username).get()
                self.assertEqual(user.status_id, Status.objects.blocked)
            else:
                self.assertEqual(record.active, 'yes')
