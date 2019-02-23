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
        self.prerequisites.role_superuser_two()

    def login_ok(self):
        # get API response
        data = {'username': self.prerequisites.username_two, 'password': self.prerequisites.password_two}
        self.client.post(self.path, data=data, format='json')
        query = AccessLog.objects.filter(username=self.prerequisites.username_two).all()[0]
        self.assertEqual(query.action, 'login')
        self.assertEqual(query.attempt, 1)
        self.assertEqual(query.active, '--')

    def login_attempts(self):
        # get API response
        data = {'username': self.prerequisites.username_two, 'password': 'sadasdasd'}
        # login for the maximum allowed attempts
        for idx in range(settings.MAX_LOGIN_ATTEMPTS + 1):
            self.client.post(self.path, data=data, format='json')
        query = AccessLog.objects.filter(username=self.prerequisites.username_two).all()
        for idx, record in enumerate(query):
            self.assertEqual(record.action, 'attempt')
            self.assertEqual(record.attempt, idx + 1)
            if idx + 1 > settings.MAX_LOGIN_ATTEMPTS:
                self.assertEqual(record.active, 'no')
                user = Users.objects.filter(username=self.prerequisites.username_two).get()
                self.assertEqual(user.status_id, Status.objects.blocked)
            else:
                self.assertEqual(record.active, 'yes')

    def login_attempts_nok(self):
        self.login_attempts()
        data = {'username': self.prerequisites.username_two, 'password': 'sadasdasd'}
        user = Users.objects.filter(username=self.prerequisites.username_two).get()
        # un-block user to grant new attempts
        self.prerequisites.auth(self.client)
        path = '{}/{}/{}/{}'.format(reverse('users-list'), user.lifecycle_id, user.version, 'productive')
        response = self.client.patch(path, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['status'], 'productive')
        # login again
        self.client.post(self.path, data=data, format='json')
        record = AccessLog.objects.filter(username=self.prerequisites.username_two).order_by('-timestamp')[0]
        self.assertEqual(record.action, 'attempt')
        self.assertEqual(record.attempt, 1)
        self.assertEqual(record.active, 'yes')

    def login_attempts_ok(self):
        self.login_attempts()
        data = {'username': self.prerequisites.username_two, 'password': self.prerequisites.password_two}
        user = Users.objects.filter(username=self.prerequisites.username_two).get()
        # un-block user to grant new attempts
        self.prerequisites.auth(self.client)
        path = '{}/{}/{}/{}'.format(reverse('users-list'), user.lifecycle_id, user.version, 'productive')
        response = self.client.patch(path, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['status'], 'productive')
        # login again
        self.client.post(self.path, data=data, format='json')
        record = AccessLog.objects.filter(username=self.prerequisites.username_two).order_by('-timestamp')[0]
        self.assertEqual(record.action, 'login')
        self.assertEqual(record.attempt, 1)
        self.assertEqual(record.active, '--')
