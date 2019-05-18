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
from django.test import Client

# rest framework imports
from rest_framework import status
from rest_framework.test import APITestCase

# app imports
from . import Prerequisites
from ..models import AccessLog, Users
from basics.models import Status, CentralLog


class Authenticate(APITestCase):
    def __init__(self, *args, **kwargs):
        super(Authenticate, self).__init__(*args, **kwargs)
        self.prerequisites = Prerequisites()
        self.path = reverse('login-view')

    def setUp(self):
        self.client = Client()
        self.prerequisites.role_superuser()
        self.prerequisites.role_superuser_two()
        Users.objects.create_superuser(username='soduser', password=self.prerequisites.password, role='all,all_two',
                                       email=self.prerequisites.email)

    def test_400_both(self):
        # get API response
        data = {'username': 'asdasdasd', 'password': 'sadasdasd'}
        response = self.client.post(self.path, data=data, content_type='application/json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_400_username(self):
        # get API response
        data = {'username': 'asdasdasd', 'password': self.prerequisites.password}
        response = self.client.post(self.path, data=data, content_type='application/json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_400_password(self):
        # get API response
        data = {'username': self.prerequisites.username, 'password': 'sadasdasd'}
        response = self.client.post(self.path, data=data, content_type='application/json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    # FO-137: check for 400 response at missing payload
    def test_400_missing_password(self):
        # get API response
        data = {'username': self.prerequisites.username}
        response = self.client.post(self.path, data=data, content_type='application/json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    # FO-137: check for 400 response at missing payload
    def test_400_missing_username(self):
        # get API response
        data = {'password': 'sadasdasd'}
        response = self.client.post(self.path, data=data, content_type='application/json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    # FO-137: check for 400 response at missing payload
    def test_400_missing_both(self):
        # get API response
        response = self.client.post(self.path, content_type='application/json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_200(self):
        # get API response
        data = {'username': self.prerequisites.username, 'password': self.prerequisites.password}
        response = self.client.post(self.path, data=data, content_type='application/json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)


class AuthenticateLogging(APITestCase):
    def __init__(self, *args, **kwargs):
        super(AuthenticateLogging, self).__init__(*args, **kwargs)
        self.prerequisites = Prerequisites()
        self.path = reverse('login-view')
        self.access_log = AccessLog

    def setUp(self):
        self.client = Client()
        self.prerequisites.role_superuser()
        self.prerequisites.role_superuser_two()

    def test_login_ok(self):
        # get API response
        data = {'username': self.prerequisites.username_two, 'password': self.prerequisites.password_two}
        self.client.post(self.path, data=data, content_type='application/json')
        query = AccessLog.objects.filter(user=self.prerequisites.username_two).all()[0]
        self.assertEqual(query.action, settings.DEFAULT_LOG_LOGIN)
        self.assertEqual(query.attempt, '1')
        self.assertEqual(query.active, '--')
        # verify log record
        self.assertEqual(CentralLog.objects.filter(log_id=query.id).exists(), True)
        central_record = CentralLog.objects.filter(log_id=query.id).get()
        self.assertEqual(query.action, central_record.action)
        self.assertEqual(query.user, central_record.user)
        self.assertEqual(AccessLog.MODEL_CONTEXT, central_record.context)

    def test_login_attempts(self):
        # get API response
        data = {'username': self.prerequisites.username_two, 'password': 'sadasdasd'}
        # login for the maximum allowed attempts
        for idx in range(settings.MAX_LOGIN_ATTEMPTS + 1):
            self.client.post(self.path, data=data, content_type='application/json')
        query = AccessLog.objects.filter(user=self.prerequisites.username_two).all()
        for idx, record in enumerate(query):
            self.assertEqual(record.action, settings.DEFAULT_LOG_ATTEMPT)
            self.assertEqual(int(record.attempt), idx + 1)
            if idx + 1 > settings.MAX_LOGIN_ATTEMPTS:
                self.assertEqual(record.active, 'no')
                user = Users.objects.filter(username=self.prerequisites.username_two).get()
                self.assertEqual(user.status_id, Status.objects.blocked)
            else:
                self.assertEqual(record.active, 'yes')
            # verify log record
            self.assertEqual(CentralLog.objects.filter(log_id=record.id).exists(), True)
            central_record = CentralLog.objects.filter(log_id=record.id).get()
            self.assertEqual(record.action, central_record.action)
            self.assertEqual(record.user, central_record.user)
            self.assertEqual(AccessLog.MODEL_CONTEXT, central_record.context)

    def test_login_attempts_nok(self):
        self.test_login_attempts()
        data = {'username': self.prerequisites.username_two, 'password': 'sadasdasd'}
        user = Users.objects.filter(username=self.prerequisites.username_two).get()
        # un-block user to grant new attempts
        self.prerequisites.auth(self.client)
        # get csrf
        csrf_token = self.prerequisites.get_csrf(self.client, reverse('users-list'))
        path = '{}/{}/{}/{}'.format(reverse('users-list'), user.lifecycle_id, user.version, 'productive',
                                    HTTP_X_CSRFTOKEN=csrf_token)
        response = self.client.patch(path, content_type='application/json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['status'], 'productive')
        # login again
        self.client.post(self.path, data=data, content_type='application/json')
        record = AccessLog.objects.filter(user=self.prerequisites.username_two).order_by('-timestamp')[0]
        self.assertEqual(record.action, settings.DEFAULT_LOG_ATTEMPT)
        self.assertEqual(int(record.attempt), 1)
        self.assertEqual(record.active, 'yes')
        # verify log record
        self.assertEqual(CentralLog.objects.filter(log_id=record.id).exists(), True)
        central_record = CentralLog.objects.filter(log_id=record.id).get()
        self.assertEqual(record.action, central_record.action)
        self.assertEqual(record.user, central_record.user)
        self.assertEqual(AccessLog.MODEL_CONTEXT, central_record.context)

    def test_login_attempts_ok(self):
        self.test_login_attempts()
        data = {'username': self.prerequisites.username_two, 'password': self.prerequisites.password_two}
        user = Users.objects.filter(username=self.prerequisites.username_two).get()
        # un-block user to grant new attempts
        self.prerequisites.auth(self.client)
        # get csrf
        csrf_token = self.prerequisites.get_csrf(self.client, reverse('users-list'))
        path = '{}/{}/{}/{}'.format(reverse('users-list'), user.lifecycle_id, user.version, 'productive',
                                    HTTP_X_CSRFTOKEN=csrf_token)
        response = self.client.patch(path, content_type='application/json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['status'], 'productive')
        # login again
        self.client.post(self.path, data=data, content_type='application/json')
        record = AccessLog.objects.filter(user=self.prerequisites.username_two).order_by('-timestamp')[0]
        self.assertEqual(record.action, settings.DEFAULT_LOG_LOGIN)
        self.assertEqual(int(record.attempt), 1)
        self.assertEqual(record.active, '--')
        # verify log record
        self.assertEqual(CentralLog.objects.filter(log_id=record.id).exists(), True)
        central_record = CentralLog.objects.filter(log_id=record.id).get()
        self.assertEqual(record.action, central_record.action)
        self.assertEqual(record.user, central_record.user)
        self.assertEqual(AccessLog.MODEL_CONTEXT, central_record.context)


class AuthenticateSoD(APITestCase):
    def __init__(self, *args, **kwargs):
        super(AuthenticateSoD, self).__init__(*args, **kwargs)
        self.prerequisites = Prerequisites()
        self.path = reverse('login-view')

    def setUp(self):
        self.client = Client()
        self.prerequisites.role_superuser()
        self.prerequisites.role_superuser_two()
        Users.objects.create_superuser(username='soduser', password=self.prerequisites.password, role='all,all_two',
                                       email=self.prerequisites.email)

    def test_200_no_sod(self):
        # get API response
        data = {'username': 'soduser', 'password': self.prerequisites.password}
        response = self.client.post(self.path, data=data, content_type='application/json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_400_sod(self):
        # add conflict and push to prod
        # authenticate
        self.prerequisites.auth(self.client)
        # get csrf
        base_path = reverse('sod-list')
        csrf_token = self.prerequisites.get_csrf(self.client, path=base_path)
        # get API response
        response = self.client.post(base_path, data={'base': 'all', 'conflict': 'all_two'},
                                    content_type='application/json', HTTP_X_CSRFTOKEN=csrf_token)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        # start circulation
        _status = 'circulation'
        path = '{}/{}/{}/{}'.format(base_path, response.data['lifecycle_id'], 1, _status)
        response_circ = self.client.patch(path, content_type='application/json', HTTP_X_CSRFTOKEN=csrf_token)
        self.assertEqual(response_circ.status_code, status.HTTP_200_OK)

        # push to productive
        # auth with second user to avoid SoD
        self.prerequisites.auth_two(self.client)
        # get csrf
        csrf_token = self.prerequisites.get_csrf(self.client, path=base_path)
        _status = 'productive'
        path = '{}/{}/{}/{}'.format(base_path, response.data['lifecycle_id'], 1, _status)
        response_prod = self.client.patch(path, content_type='application/json', HTTP_X_CSRFTOKEN=csrf_token)
        self.assertEqual(response_prod.status_code, status.HTTP_200_OK)

        # try to log in again
        data = {'username': 'soduser', 'password': self.prerequisites.password}
        response = self.client.post(self.path, data=data, content_type='application/json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
