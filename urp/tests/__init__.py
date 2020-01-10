"""
opengxp.org
Copyright (C) 2019  Henrik Baran

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
from django.apps import apps
from django.conf import settings
from django.core.management import call_command
from django.test import Client
from django.urls import reverse
from django.utils import timezone

# rest framework imports
from rest_framework import status
from rest_framework.test import APITestCase

# app imports
from ..models import Users
from basics.models import CentralLog, Status
from basics.custom import str_list_change


class Prerequisites(object):
    def __init__(self, base_path=None):
        self.username = 'superuser'
        self.password = 'test1asda2234'
        self.email = 'test@opengxp.org'
        self.base_path = base_path
        # second superuser
        self.username_two = 'superusertesttwo'
        self.password_two = 'test123123123asd'
        self.email_two = 'usertwo@opengxp.org'
        # third superuser
        self.username_three = 'superuserthree'
        self.password_three = 'test123123123asd'
        self.email_three = 'userthree@opengxp.org'
        # user for tests without permissions
        self.username_no_perm = 'usernoperms'
        self.email_four = 'userfour@opengxp.org'
        # user for valid from tests
        self.username_valid_from = 'uservalidfrom'
        self.email_five = 'userfive@opengxp.org'
        # user for read only permissions
        self.username_no_write_perm = 'usernowriteperms'
        self.email_six = 'usersix@opengxp.org'
        # user for no new version_archived permission
        self.username_no_version_archived = 'usernoversionarchived'
        self.email_seven = 'userseven@opengxp.org'

    def create_record(self, ext_client, data):
        # authenticate
        self.auth(ext_client)
        # get csrf
        csrf_token = self.get_csrf(ext_client)
        # get API response
        response = ext_client.post(self.base_path, data=data, content_type='application/json',
                                   HTTP_X_CSRFTOKEN=csrf_token)
        if response.status_code == status.HTTP_201_CREATED:
            return response.data
        else:
            raise AssertionError('Error Code: {}, Can not create prerequisite record.\n'
                                 'Error Message: {}'.format(response.status_code, response.data))

    def create_record_manual(self, ext_client, data, path):
        # authenticate
        self.auth(ext_client)
        # get csrf
        csrf_token = self.get_csrf(ext_client)
        # get API response
        response = ext_client.post(path, data=data, content_type='application/json', HTTP_X_CSRFTOKEN=csrf_token)
        if response.status_code == status.HTTP_201_CREATED:
            return response.data
        else:
            raise AssertionError('Error Code: {}, Can not create manual prerequisite record.\n'
                                 'Error Message: {}'.format(response.status_code, response.data))

    def create_record_manual_status(self, ext_client, data, path):
        # authenticate
        self.auth(ext_client)
        # get csrf
        csrf_token = self.get_csrf(ext_client)
        # get API response
        response = ext_client.post(path, data=data, content_type='application/json', HTTP_X_CSRFTOKEN=csrf_token)
        if response.status_code != status.HTTP_201_CREATED:
            raise AssertionError('Error Code: {}, Can not create manual prerequisite record.\n'
                                 'Error Message: {}'.format(response.status_code, response.data))
        # start circulation
        status_path = '{}/{}/1/circulation'.format(path, response.data['lifecycle_id'])
        response_circ = ext_client.patch(status_path, content_type='application/json', HTTP_X_CSRFTOKEN=csrf_token)
        if response_circ.status_code != status.HTTP_200_OK:
            raise AssertionError('Error Code: {}, Can not circulate manual prerequisite record.\n'
                                 'Error Message: {}'.format(response.status_code, response.data))
        # auth other user and set productive
        self.auth_two(ext_client)
        # get csrf
        csrf_token = self.get_csrf(ext_client)
        status_path = '{}/{}/1/productive'.format(path, response.data['lifecycle_id'])
        response_prod = ext_client.patch(status_path, content_type='application/json', HTTP_X_CSRFTOKEN=csrf_token)
        if response_prod.status_code != status.HTTP_200_OK:
            raise AssertionError('Error Code: {}, Can not approve manual prerequisite record.\n'
                                 'Error Message: {}'.format(response.status_code, response.data))
        return response_prod.data

    def role_superuser(self):
        call_command('initialize-settings')
        call_command('initialize-status')
        call_command('collect-permissions')
        role = 'all'
        call_command('create-role', name=role)
        Users.objects.create_superuser(username=self.username, password=self.password, role=role, email=self.email,
                                       initial_password=False)

    def role_superuser_two(self):
        role = 'all_two'
        call_command('create-role', name=role)
        Users.objects.create_superuser(username=self.username_two, password=self.password_two, role=role,
                                       email=self.email_two, initial_password=False)

    def role_superuser_three(self):
        role = 'all_three'
        call_command('create-role', name=role)
        Users.objects.create_superuser(username=self.username_three, password=self.password_three, role=role,
                                       email=self.email_three, initial_password=False)

    def role_no_permissions(self):
        role = 'no_perms'
        call_command('create-role', name=role, permissions='xx.xx,xx.xx')
        Users.objects.create_superuser(username=self.username_no_perm, password=self.password, role=role,
                                       email=self.email_four, initial_password=False)

    def role_no_write_permissions(self):
        models = apps.all_models['urp']
        models.update(apps.all_models['basics'])
        perms = ''
        for model in models:
            # add read for each dialog
            perms += '{}.01,'.format(models[model].MODEL_ID)
        role = 'no_write_perms'
        call_command('create-role', name=role, permissions=perms[:-1])
        Users.objects.create_superuser(username=self.username_no_write_perm, password=self.password, role=role,
                                       email=self.email_six, initial_password=False)

    def role_no_version_archived(self):
        models = apps.all_models['urp']
        models.update(apps.all_models['basics'])
        perms = ''
        for model in models:
            # add read for each dialog
            perms += '{}.01,'.format(models[model].MODEL_ID)
            # add version for each dialog
            perms += '{}.11,'.format(models[model].MODEL_ID)
        role = 'no_version_archived'
        call_command('create-role', name=role, permissions=perms[:-1])
        Users.objects.create_superuser(username=self.username_no_version_archived, password=self.password, role=role,
                                       email=self.email_seven, initial_password=False)

    def role_past_valid_from(self):
        role = 'past_valid_from'
        call_command('create-role', name=role, valid_from='01-01-2016 00:00:00')
        Users.objects.create_superuser(username=self.username_valid_from, password=self.password, role=role,
                                       email=self.email_five, initial_password=False)

    def auth(self, ext_client):
        ext_client.logout()
        response = ext_client.login(username=self.username, password=self.password)
        assert response is True
        # save last touch now timestamp to session to prevent auto logout error
        session = ext_client.session
        session['last_touch'] = timezone.now()
        session.save()

    def auth_two(self, ext_client):
        ext_client.logout()
        response = ext_client.login(username=self.username_two, password=self.password_two)
        assert response is True
        # save last touch now timestamp to session to prevent auto logout error
        session = ext_client.session
        session['last_touch'] = timezone.now()
        session.save()

    def auth_three(self, ext_client):
        ext_client.logout()
        response = ext_client.login(username=self.username_three, password=self.password_three)
        assert response is True
        # save last touch now timestamp to session to prevent auto logout error
        session = ext_client.session
        session['last_touch'] = timezone.now()
        session.save()

    def auth_no_perms(self, ext_client):
        ext_client.logout()
        response = ext_client.login(username=self.username_no_perm, password=self.password)
        assert response is True
        # save last touch now timestamp to session to prevent auto logout error
        session = ext_client.session
        session['last_touch'] = timezone.now()
        session.save()

    def auth_not_valid_roles(self, ext_client):
        ext_client.logout()
        response = ext_client.login(username=self.username_valid_from, password=self.password)
        assert response is True
        # save last touch now timestamp to session to prevent auto logout error
        session = ext_client.session
        session['last_touch'] = timezone.now()
        session.save()

    def auth_no_write_perms(self, ext_client):
        ext_client.logout()
        response = ext_client.login(username=self.username_no_write_perm, password=self.password)
        assert response is True
        # save last touch now timestamp to session to prevent auto logout error
        session = ext_client.session
        session['last_touch'] = timezone.now()
        session.save()

    def auth_no_version_archived(self, ext_client):
        ext_client.logout()
        response = ext_client.login(username=self.username_no_version_archived, password=self.password)
        assert response is True
        # save last touch now timestamp to session to prevent auto logout error
        session = ext_client.session
        session['last_touch'] = timezone.now()
        session.save()

    @staticmethod
    def verify_csrf(response):
        return response.cookies['csrftoken']

    def get_csrf(self, ext_client, path=None):
        if not path:
            path = self.base_path
        response = ext_client.get(path, content_type='application/json')
        assert response.status_code == status.HTTP_200_OK
        return response.cookies['csrftoken'].value

    # FO-121: method to block the logged in superuser
    def block_auth_user(self, ext_client):
        # get csrf
        csrf_token = self.get_csrf(ext_client, path=reverse('users-list'))
        user = Users.objects.filter(username=self.username, status=Status.objects.productive, version=1).get()
        # block superuser
        path = '{}/{}/1/blocked'.format(reverse('users-list'), user.lifecycle_id)
        response = ext_client.patch(path, content_type='application/json', HTTP_X_CSRFTOKEN=csrf_token)
        assert response.status_code == status.HTTP_200_OK

    # FO-121: method to make the logged in superuser invalid
    def invalid_auth_user(self, ext_client):
        # get csrf
        csrf_token = self.get_csrf(ext_client, path=reverse('users-list'))
        user = Users.objects.filter(username=self.username, status=Status.objects.productive, version=1).get()
        # new version
        path = '{}/{}/1'.format(reverse('users-list'), user.lifecycle_id)
        response = ext_client.post(path, content_type='application/json', HTTP_X_CSRFTOKEN=csrf_token)
        assert response.status_code == status.HTTP_201_CREATED
        # update draft of second version to be invalid
        path = '{}/{}/2'.format(reverse('users-list'), user.lifecycle_id)
        data = {'username': self.username,
                'roles': ['all'],
                'email': 'test@opengxp.org',
                'valid_from': timezone.now(),
                'valid_to': timezone.now(),
                'ldap': False}
        response = ext_client.patch(path, data=data, content_type='application/json', HTTP_X_CSRFTOKEN=csrf_token)
        assert response.status_code == status.HTTP_200_OK
        # auth with second user to avoid SoD and set set in circulation
        self.role_superuser_three()
        self.auth_three(ext_client)
        csrf_token = self.get_csrf(ext_client, path=reverse('users-list'))
        path = '{}/{}/2/circulation'.format(reverse('users-list'), user.lifecycle_id)
        response = ext_client.patch(path, content_type='application/json', HTTP_X_CSRFTOKEN=csrf_token)
        assert response.status_code == status.HTTP_200_OK
        # auth again with user to be invalid
        self.auth(ext_client)
        csrf_token = self.get_csrf(ext_client, path=reverse('users-list'))
        path = '{}/{}/2/productive'.format(reverse('users-list'), user.lifecycle_id)
        response = ext_client.patch(path, content_type='application/json', HTTP_X_CSRFTOKEN=csrf_token)
        assert response.status_code == status.HTTP_200_OK
        return csrf_token

    def change_dialog_com_sig(self, ext_client, mode, model, perm, value):
        # authenticate
        self.auth(ext_client)
        # get csrf
        csrf_token = self.get_csrf(ext_client)
        # prepare url
        path = '{}/dialog.{}.{}.{}'.format(reverse('settings-list'), model, mode, perm)
        # get API response
        response = ext_client.patch(path, data={'value': value}, content_type='application/json',
                                    HTTP_X_CSRFTOKEN=csrf_token)
        if response.status_code != status.HTTP_200_OK:
            raise AssertionError('Error Code: {}, Can not change dialog settings.'
                                 .format(response.status_code))


def log_records(model, action, data, access_log=None, _status=True, sub_tables=True, rtd=None):
    data['action'] = action
    # remove valid field, because its read only and not in db
    del data['valid']
    del data['unique']
    if 'valid_from_local' in data:
        del data['valid_from_local']
    if 'valid_to_local' in data:
        del data['valid_to_local']
    # human readable status is a read only field and not in db, but uuid
    if _status or rtd:
        data['status_id'] = Status.objects.status_by_text(data['status'])
        del data['status']
    # get log model of tested model
    if not access_log:
        log_model = model.objects.LOG_TABLE
    else:
        log_model = access_log

    # build query structure if sub_table
    if model.sub_tables():
        dummy_obj = model()
        # parent table
        data_parent = data.copy()
        for value in dummy_obj.sub_tables().values():
            field = value.replace('linked_', '')
            del data_parent[field]
        try:
            log_model.objects.filter(**data_parent).all()[0]
        except log_model.DoesNotExist or IndexError:
            assert 'No log record found for "{}".'.format(data_parent)

        # sub tables, not for status
        if sub_tables:
            for table, key in dummy_obj.sub_tables().items():
                field = key.replace('linked_', '')
                log_table = table.objects.LOG_TABLE
                for record in data[field]:
                    # transform predecessors to string
                    record = str_list_change(data=record, key='predecessors', target=str)

                    # add parent data
                    record['lifecycle_id'] = data['lifecycle_id']
                    record['version'] = data['version']
                    record['action'] = action
                    try:
                        log_table.objects.filter(**record).all()[0]
                    except log_table.DoesNotExist or IndexError:
                        assert 'No log record found for "{}".'.format(record)
        return True

    try:
        query = log_model.objects.filter(**data).all()[0]
    except model.DoesNotExist or IndexError:
        assert 'No log record found for "{}".'.format(data)
    else:
        return CentralLog.objects.filter(log_id=query.id).exists()


class GetAll(APITestCase):
    def __init__(self, *args, **kwargs):
        super(GetAll, self).__init__(*args, **kwargs)
        self.prerequisites = Prerequisites()

        # placeholders
        self.base_path = None
        self.model = None
        self.serializer = None
        self.filter = {}

        # flag for execution
        self.execute = False
        self.perm_required = True

    def setUp(self):
        if self.execute:
            self.client = Client()
            self.prerequisites.role_superuser()
            self.prerequisites.role_no_permissions()
            self.ok_path = self.base_path

    def test_401(self):
        if self.execute:
            # reset auth
            self.client.logout()
            # get API response
            response = self.client.get(self.ok_path, content_type='application/json')
            self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_403(self):
        if self.execute and self.perm_required:
            # authenticate
            self.prerequisites.auth_no_perms(self.client)
            # get API response
            response = self.client.get(self.ok_path, content_type='application/json')
            self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    # test to verify that response includes csrf token
    def test_200_csrf(self):
        if self.execute:
            # authenticate
            self.prerequisites.auth(self.client)
            # get API response
            response = self.client.get(self.ok_path, content_type='application/json')
            self.assertIsNotNone(self.prerequisites.verify_csrf(response))

    def test_200(self):
        if self.execute:
            # authenticate
            self.prerequisites.auth(self.client)
            # get API response
            response = self.client.get(self.ok_path, content_type='application/json')
            # get data from db
            if self.model.MODEL_ID == '02':
                limit = settings.DEFAULT_PERMISSIONS_PAGINATION_LIMIT
            else:
                limit = settings.PROFILE_DEFAULT_PAGINATION_LIMIT
            query = self.model.objects.filter(**self.filter).all()[:limit]
            serializer = self.serializer(query, many=True, context={'user': self.prerequisites.username})
            self.assertEqual(response.data['results'], serializer.data)
            self.assertEqual(response.status_code, status.HTTP_200_OK)

    # FO-121: new test to verify user cannot proceed when blocked
    def test_401_blocked(self):
        if self.execute:
            # authenticate
            self.prerequisites.auth(self.client)
            # block authenticated user
            self.prerequisites.block_auth_user(self.client)
            # get API response
            response = self.client.get(self.ok_path, content_type='application/json')
            self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    # FO-121: new test to verify user cannot proceed when not valid anymore
    def test_401_invalid(self):
        if self.execute:
            # authenticate
            self.prerequisites.auth(self.client)
            # block authenticated user
            self.prerequisites.invalid_auth_user(self.client)
            # get API response
            response = self.client.get(self.ok_path, content_type='application/json')
            self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


class GetOne(APITestCase):
    def __init__(self, *args, **kwargs):
        super(GetOne, self).__init__(*args, **kwargs)
        # placeholders
        self.base_path = None
        self.model = None
        self.prerequisites = None
        self.serializer = None
        self.ok_object_data = None
        self.pre_data = None

        # flag for execution
        self.execute = False
        self.rtd = False

    def setUp(self):
        if self.execute:
            self.client = Client()
            self.prerequisites.role_superuser()
            self.prerequisites.role_superuser_two()
            self.prerequisites.role_no_permissions()
            # create ok object
            if self.pre_data:
                for record in self.pre_data:
                    if record['status']:
                        self.prerequisites.create_record_manual_status(self.client, record['data'], record['path'])
                    else:
                        self.prerequisites.create_record_manual(self.client, record['data'], record['path'])
            self.ok_object = self.prerequisites.create_record(self.client, self.ok_object_data)
            # create ok path
            if self.rtd:
                self.ok_path = '{}/{}'.format(self.base_path, self.ok_object['number'])
                self.query = {'number': self.ok_object['number']}
                self.false_path_uuid = '{}/{}'.format(self.base_path, '1231412341')
            else:
                self.ok_path = '{}/{}/{}'.format(self.base_path, self.ok_object['lifecycle_id'],
                                                 self.ok_object['version'])
                self.query = {'lifecycle_id': self.ok_object['lifecycle_id'],
                              'version': self.ok_object['version']}
                self.false_path_version = '{}/{}/{}'.format(self.base_path, self.ok_object['lifecycle_id'], 2)
                self.false_path_uuid = '{}/{}/{}'.format(self.base_path, 'cac8d0f0-ce96-421c-9327-a44e4703d26f',
                                                         self.ok_object['version'])
                self.false_path_both = '{}/{}/{}'.format(self.base_path, 'cac8d0f0-ce96-421c-9327-a44e4703d26f', 2)

    def test_401(self):
        if self.execute:
            # reset auth
            self.client.logout()
            # get API response
            response = self.client.get(self.ok_path, content_type='application/json')
            self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_403(self):
        if self.execute:
            # authenticate
            self.prerequisites.auth_no_perms(self.client)
            # get API response
            response = self.client.get(self.ok_path, content_type='application/json')
            self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_200_csrf(self):
        if self.execute:
            # authenticate
            self.prerequisites.auth(self.client)
            # get API response
            response = self.client.get(self.ok_path, content_type='application/json')
            self.assertIsNotNone(self.prerequisites.verify_csrf(response))

    def test_200(self):
        if self.execute:
            # authenticate
            self.prerequisites.auth(self.client)
            # get API response
            response = self.client.get(self.ok_path, content_type='application/json')
            # get data from db
            query = self.model.objects.get(**self.query)
            serializer = self.serializer(query, context={'user': self.prerequisites.username})
            self.assertEqual(response.data['results'], [serializer.data])
            self.assertEqual(response.status_code, status.HTTP_200_OK)

    # FO-121: new test to verify user cannot proceed when blocked
    def test_401_blocked(self):
        if self.execute:
            # authenticate
            self.prerequisites.auth(self.client)
            # block authenticated user
            self.prerequisites.block_auth_user(self.client)
            # get API response
            response = self.client.get(self.ok_path, content_type='application/json')
            self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    # FO-121: new test to verify user cannot proceed when not valid anymore
    def test_401_invalid(self):
        if self.execute:
            # authenticate
            self.prerequisites.auth(self.client)
            # block authenticated user
            self.prerequisites.invalid_auth_user(self.client)
            # get API response
            response = self.client.get(self.ok_path, content_type='application/json')
            self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_404_both(self):
        if self.execute and not self.rtd:
            # authenticate
            self.prerequisites.auth(self.client)
            # get API response
            response = self.client.get(self.false_path_both, content_type='application/json')
            self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_404_version(self):
        if self.execute and not self.rtd:
            # authenticate
            self.prerequisites.auth(self.client)
            # get API response
            response = self.client.get(self.false_path_version, content_type='application/json')
            self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_404_uuid(self):
        if self.execute:
            # authenticate
            self.prerequisites.auth(self.client)
            # get API response
            response = self.client.get(self.false_path_uuid, content_type='application/json')
            self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)


class GetOneNoStatus(APITestCase):
    def __init__(self, *args, **kwargs):
        super(GetOneNoStatus, self).__init__(*args, **kwargs)
        # placeholders
        self.base_path = None
        self.model = None
        self.prerequisites = None
        self.serializer = None
        self.ok_object_data = None
        self.ok_object_data_unique = str()
        self.data_available = False
        self.test_data = str()
        self.pre_data = None
        self.filter = {}

        # flag for execution
        self.execute = False
        self.perm_required = True

    def setUp(self):
        if self.execute:
            self.client = Client()
            self.prerequisites.role_superuser()
            self.prerequisites.role_no_permissions()
            if self.pre_data:
                for record in self.pre_data:
                    self.prerequisites.create_record_manual(self.client, record['data'], record['path'])
            if not self.data_available:
                # create ok object
                self.ok_object = self.prerequisites.create_record(self.client, self.ok_object_data)
                # create ok path
                self.ok_path = '{}/{}'.format(self.base_path, self.ok_object[self.ok_object_data_unique])
                self.query = {self.ok_object_data_unique: self.ok_object[self.ok_object_data_unique]}
            else:
                self.ok_path = '{}/{}'.format(self.base_path, self.test_data)
                self.query = {self.ok_object_data_unique: self.test_data}
            self.false_path = '{}/{}'.format(self.base_path, 'sadasuidhasdas')

    def test_401(self):
        if self.execute:
            # reset auth
            self.client.logout()
            # get API response
            response = self.client.get(self.ok_path, content_type='application/json')
            self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_403(self):
        if self.execute and self.perm_required:
            # authenticate
            self.prerequisites.auth_no_perms(self.client)
            # get API response
            response = self.client.get(self.ok_path, content_type='application/json')
            self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_200_csrf(self):
        if self.execute:
            # authenticate
            self.prerequisites.auth(self.client)
            # get API response
            response = self.client.get(self.ok_path, content_type='application/json')
            self.assertIsNotNone(self.prerequisites.verify_csrf(response))

    def test_200(self):
        if self.execute:
            # authenticate
            self.prerequisites.auth(self.client)
            # get API response
            response = self.client.get(self.ok_path, content_type='application/json')
            # get data from db
            query = self.model.objects.filter(**self.filter).get(**self.query)
            serializer = self.serializer(query)
            self.assertEqual(response.data['results'], [serializer.data])
            self.assertEqual(response.status_code, status.HTTP_200_OK)

    # FO-121: new test to verify user cannot proceed when blocked
    def test_401_blocked(self):
        if self.execute:
            # authenticate
            self.prerequisites.auth(self.client)
            # block authenticated user
            self.prerequisites.block_auth_user(self.client)
            # get API response
            response = self.client.get(self.ok_path, content_type='application/json')
            self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    # FO-121: new test to verify user cannot proceed when not valid anymore
    def test_401_invalid(self):
        if self.execute:
            # authenticate
            self.prerequisites.auth(self.client)
            # block authenticated user
            self.prerequisites.invalid_auth_user(self.client)
            # get API response
            response = self.client.get(self.ok_path, content_type='application/json')
            self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_404(self):
        if self.execute:
            # authenticate
            self.prerequisites.auth(self.client)
            # get API response
            response = self.client.get(self.false_path, content_type='application/json')
            self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)


# post
class PostNew(APITestCase):
    def __init__(self, *args, **kwargs):
        super(PostNew, self).__init__(*args, **kwargs)
        # placeholders
        self.base_path = None
        self.model = None
        self.prerequisites = None
        self.valid_payload = None
        self.invalid_payloads = None
        self.pre_data = None

        # flag for execution
        self.execute = False

        # flag for non-status managed objects
        self.status = True

        # flag for runtime objects
        self.rtd = False

    def setUp(self):
        if self.execute:
            self.client = Client(enforce_csrf_checks=True)
            self.prerequisites.role_superuser()
            self.prerequisites.role_superuser_two()
            self.prerequisites.role_no_write_permissions()
            self.ok_path = self.base_path
            if self.pre_data:
                for record in self.pre_data:
                    if record['status']:
                        self.prerequisites.create_record_manual_status(self.client, record['data'], record['path'])
                    else:
                        self.prerequisites.create_record_manual(self.client, record['data'], record['path'])

    def test_401(self):
        if self.execute:
            # reset auth
            self.client.logout()
            # get API response
            response = self.client.post(self.ok_path, data=self.valid_payload, content_type='application/json')
            self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_403_csrf(self):
        if self.execute:
            # authenticate
            self.prerequisites.auth(self.client)
            # get API response
            response = self.client.post(self.ok_path, data=self.valid_payload, content_type='application/json')
            self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_403_permission(self):
        if self.execute:
            # authenticate
            self.prerequisites.auth_no_write_perms(self.client)
            # get csrf
            csrf_token = self.prerequisites.get_csrf(self.client)
            # get API response
            response = self.client.post(self.ok_path, data=self.valid_payload, content_type='application/json',
                                        HTTP_X_CSRFTOKEN=csrf_token)
            self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_400(self):
        if self.execute:
            # authenticate
            self.prerequisites.auth(self.client)
            # get csrf
            csrf_token = self.prerequisites.get_csrf(self.client)
            # get API response
            for payload in self.invalid_payloads:
                response = self.client.post(self.ok_path, data=payload, content_type='application/json',
                                            HTTP_X_CSRFTOKEN=csrf_token)
                self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_201(self):
        if self.execute:
            # authenticate
            self.prerequisites.auth(self.client)
            # get csrf
            csrf_token = self.prerequisites.get_csrf(self.client)
            # get API response
            response = self.client.post(self.ok_path, data=self.valid_payload, content_type='application/json',
                                        HTTP_X_CSRFTOKEN=csrf_token)
            self.assertEqual(response.status_code, status.HTTP_201_CREATED)
            if self.status:
                self.assertEqual(response.data['version'], 1)
                self.assertEqual(response.data['status'], 'draft')
            if self.rtd:
                self.assertEqual(response.data['status'], 'created')
            # verify log record
            self.assertEqual(log_records(model=self.model, data=response.data, action=settings.DEFAULT_LOG_CREATE,
                                         _status=self.status, rtd=self.rtd), True)

    def test_comment(self):
        if self.execute:
            # authenticate
            self.prerequisites.auth(self.client)

            # change settings for mandatory comment
            self.prerequisites.change_dialog_com_sig(ext_client=self.client, mode='comment', value='mandatory',
                                                     model=self.model.MODEL_CONTEXT.lower(), perm='add')

            # get csrf
            csrf_token = self.prerequisites.get_csrf(self.client)

            # fail when no comment is provided
            response = self.client.post(self.ok_path, data=self.valid_payload, content_type='application/json',
                                        HTTP_X_CSRFTOKEN=csrf_token)
            self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

            # positive response if comment is provided
            data = self.valid_payload.copy()
            data['com'] = 'test'
            response = self.client.post(self.ok_path, data=data, content_type='application/json',
                                        HTTP_X_CSRFTOKEN=csrf_token)
            self.assertEqual(response.status_code, status.HTTP_201_CREATED)

    def test_signature(self):
        if self.execute:
            # authenticate
            self.prerequisites.auth(self.client)

            # change settings for mandatory comment
            self.prerequisites.change_dialog_com_sig(ext_client=self.client, mode='signature', value='signature',
                                                     model=self.model.MODEL_CONTEXT.lower(), perm='add')

            # get csrf
            csrf_token = self.prerequisites.get_csrf(self.client)

            # fail when no signature is provided
            response = self.client.post(self.ok_path, data=self.valid_payload, content_type='application/json',
                                        HTTP_X_CSRFTOKEN=csrf_token)
            self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

            # positive response if signature is provided
            data = self.valid_payload.copy()
            data['sig_user'] = self.prerequisites.username
            data['sig_pw'] = self.prerequisites.password
            response = self.client.post(self.ok_path, data=data, content_type='application/json',
                                        HTTP_X_CSRFTOKEN=csrf_token)
            self.assertEqual(response.status_code, status.HTTP_201_CREATED)

    # FO-121: new test to verify user cannot proceed when blocked
    def test_401_blocked(self):
        if self.execute:
            # authenticate
            self.prerequisites.auth(self.client)
            # get csrf
            csrf_token = self.prerequisites.get_csrf(self.client)
            # block authenticated user
            self.prerequisites.block_auth_user(self.client)
            # get API response
            response = self.client.post(self.ok_path, data=self.valid_payload, content_type='application/json',
                                        HTTP_X_CSRFTOKEN=csrf_token)
            self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    # FO-121: new test to verify user cannot proceed when not valid anymore
    def test_401_invalid(self):
        if self.execute:
            # authenticate
            self.prerequisites.auth(self.client)
            # block authenticated user
            csrf_token = self.prerequisites.invalid_auth_user(self.client)
            # get API response
            response = self.client.post(self.ok_path, data=self.valid_payload, content_type='application/json',
                                        HTTP_X_CSRFTOKEN=csrf_token)
            self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_400_second(self):
        if self.execute and not self.rtd:
            self.test_201()
            # authenticate
            self.prerequisites.auth(self.client)
            # get csrf
            csrf_token = self.prerequisites.get_csrf(self.client)
            # get API response
            response = self.client.post(self.ok_path, data=self.valid_payload, content_type='application/json',
                                        HTTP_X_CSRFTOKEN=csrf_token)
            self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


# post
class PostNewVersion(APITestCase):
    def __init__(self, *args, **kwargs):
        super(PostNewVersion, self).__init__(*args, **kwargs)

        # placeholders
        self.base_path = None
        self.model = None
        self.serializer = None
        self.ok_object_data = None
        self.fail_object_draft_data = None
        self.fail_object_circulation_data = None
        self.prerequisites = None
        self.pre_data = None

        # flag for execution
        self.execute = False

    def setUp(self):
        if self.execute:
            self.client = Client(enforce_csrf_checks=True)
            self.prerequisites.role_superuser()
            self.prerequisites.role_superuser_two()
            self.prerequisites.role_no_write_permissions()
            self.prerequisites.role_no_version_archived()
            # create ok object in status draft
            if self.pre_data:
                for record in self.pre_data:
                    if record['status']:
                        self.prerequisites.create_record_manual_status(self.client, record['data'], record['path'])
                    else:
                        self.prerequisites.create_record_manual(self.client, record['data'], record['path'])
            self.ok_object = self.prerequisites.create_record(self.client, self.ok_object_data)
            # push ok object to ok status
            # authenticate
            self.prerequisites.auth(self.client)
            # get csrf
            csrf_token = self.prerequisites.get_csrf(self.client)
            path = '{}/{}/{}/{}'.format(self.base_path, self.ok_object['lifecycle_id'], self.ok_object['version'],
                                        'circulation')
            self.client.patch(path, content_type='application/json', HTTP_X_CSRFTOKEN=csrf_token)
            # auth with second user to avoid SoD
            self.prerequisites.auth_two(self.client)
            # get csrf
            csrf_token = self.prerequisites.get_csrf(self.client)
            path = '{}/{}/{}/{}'.format(self.base_path, self.ok_object['lifecycle_id'], self.ok_object['version'],
                                        'productive')
            self.client.patch(path, content_type='application/json', HTTP_X_CSRFTOKEN=csrf_token)
            # create ok path
            self.ok_path = '{}/{}/{}'.format(self.base_path, self.ok_object['lifecycle_id'], self.ok_object['version'])
            self.query = {'lifecycle_id': self.ok_object['lifecycle_id'],
                          'version': self.ok_object['version']}
            # create not ok paths
            self.false_path_version = '{}/{}/{}'.format(self.base_path, self.ok_object['lifecycle_id'], 2)
            self.false_path_uuid = '{}/{}/{}'.format(self.base_path, 'cac8d0f0-ce96-421c-9327-a44e4703d26f',
                                                     self.ok_object['version'])
            self.false_path_both = '{}/{}/{}'.format(self.base_path, 'cac8d0f0-ce96-421c-9327-a44e4703d26f', 2)

            # create fail object draft
            self.fail_object_draft = self.prerequisites.create_record(self.client, self.fail_object_draft_data)
            self.fail_path_draft = '{}/{}/{}'.format(self.base_path, self.fail_object_draft['lifecycle_id'],
                                                     self.fail_object_draft['version'])

            # create fail object circulation
            self.fail_object_circulation = self.prerequisites.create_record(self.client,
                                                                            self.fail_object_circulation_data)
            path = '{}/{}/{}/{}'.format(self.base_path, self.fail_object_circulation['lifecycle_id'],
                                        self.fail_object_circulation['version'], 'circulation')
            self.client.patch(path, content_type='application/json', HTTP_X_CSRFTOKEN=csrf_token)
            self.fail_path_circulation = '{}/{}/{}'.format(self.base_path, self.fail_object_circulation['lifecycle_id'],
                                                           self.fail_object_circulation['version'])

    def test_401(self):
        if self.execute:
            # reset auth
            self.client.logout()
            # get API response
            response = self.client.post(self.ok_path, content_type='application/json')
            self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_403_csrf(self):
        if self.execute:
            # authenticate
            self.prerequisites.auth(self.client)
            # get API response
            response = self.client.post(self.ok_path, content_type='application/json')
            self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_403_permission(self):
        if self.execute:
            # authenticate
            self.prerequisites.auth_no_write_perms(self.client)
            # get csrf
            csrf_token = self.prerequisites.get_csrf(self.client)
            # get API response
            response = self.client.post(self.ok_path, content_type='application/json', HTTP_X_CSRFTOKEN=csrf_token)
            self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_403_permission_archived(self):
        if self.execute:
            # authenticate
            self.prerequisites.auth(self.client)
            # get csrf
            csrf_token = self.prerequisites.get_csrf(self.client)
            # push to status archived
            self.client.patch('{}/{}'.format(self.ok_path, 'circulation'), content_type='application/json',
                              HTTP_X_CSRFTOKEN=csrf_token)
            # auth with second user to avoid SoD
            self.prerequisites.auth_two(self.client)
            # get csrf
            csrf_token = self.prerequisites.get_csrf(self.client)
            self.client.patch('{}/{}'.format(self.ok_path, 'productive'), content_type='application/json',
                              HTTP_X_CSRFTOKEN=csrf_token)
            response = self.client.patch('{}/{}'.format(self.ok_path, 'archived'), content_type='application/json',
                                         HTTP_X_CSRFTOKEN=csrf_token)
            self.assertEqual(response.data['status'], 'archived')
            # authenticate
            self.prerequisites.auth_no_version_archived(self.client)
            # get API response
            response = self.client.post(self.ok_path, content_type='application/json', HTTP_X_CSRFTOKEN=csrf_token)
            self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_404_both(self):
        if self.execute:
            # authenticate
            self.prerequisites.auth(self.client)
            # get csrf
            csrf_token = self.prerequisites.get_csrf(self.client)
            # get API response
            response = self.client.post(self.false_path_both, content_type='application/json',
                                        HTTP_X_CSRFTOKEN=csrf_token)
            self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_404_version(self):
        if self.execute:
            # authenticate
            self.prerequisites.auth(self.client)
            # get csrf
            csrf_token = self.prerequisites.get_csrf(self.client)
            # get API response
            response = self.client.post(self.false_path_version, content_type='application/json',
                                        HTTP_X_CSRFTOKEN=csrf_token)
            self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_404_uuid(self):
        if self.execute:
            # authenticate
            self.prerequisites.auth(self.client)
            # get csrf
            csrf_token = self.prerequisites.get_csrf(self.client)
            # get API response
            response = self.client.post(self.false_path_uuid, content_type='application/json',
                                        HTTP_X_CSRFTOKEN=csrf_token)
            self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_201(self):
        if self.execute:
            # authenticate
            self.prerequisites.auth(self.client)
            # get csrf
            csrf_token = self.prerequisites.get_csrf(self.client)
            # get API response
            response = self.client.post(self.ok_path, content_type='application/json',
                                        HTTP_X_CSRFTOKEN=csrf_token)
            self.assertEqual(response.status_code, status.HTTP_201_CREATED)
            self.assertEqual(response.data['version'], 2)
            self.assertEqual(response.data['lifecycle_id'], str(self.ok_object['lifecycle_id']))
            self.assertEqual(response.data['status'], 'draft')
            # add check that data is the same, except status and version
            query = self.model.objects.get(**self.query)
            serializer = self.serializer(query, context={'user': self.prerequisites.username})
            if isinstance(self.model.UNIQUE, list):
                for field in self.model.UNIQUE:
                    self.assertEqual(response.data[field], serializer.data[field])
            else:
                self.assertEqual(response.data[self.model.UNIQUE], serializer.data[self.model.UNIQUE])
            self.assertEqual(response.data['valid_from'], serializer.data['valid_from'])
            # verify log record
            self.assertEqual(log_records(model=self.model, data=response.data, action=settings.DEFAULT_LOG_CREATE),
                             True)

    # FO-121: new test to verify user cannot proceed when blocked
    def test_401_blocked(self):
        if self.execute:
            # authenticate
            self.prerequisites.auth(self.client)
            # get csrf
            csrf_token = self.prerequisites.get_csrf(self.client)
            # block authenticated user
            self.prerequisites.block_auth_user(self.client)
            # get API response
            response = self.client.post(self.ok_path, content_type='application/json', HTTP_X_CSRFTOKEN=csrf_token)
            self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    # FO-121: new test to verify user cannot proceed when not valid anymore
    def test_401_invalid(self):
        if self.execute:
            # authenticate
            self.prerequisites.auth(self.client)
            # block authenticated user
            csrf_token = self.prerequisites.invalid_auth_user(self.client)
            # get API response
            response = self.client.post(self.ok_path, content_type='application/json', HTTP_X_CSRFTOKEN=csrf_token)
            self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_400_second(self):
        if self.execute:
            # first add a new version
            self.test_201()
            # authenticate
            self.prerequisites.auth(self.client)
            # get csrf
            csrf_token = self.prerequisites.get_csrf(self.client)
            # second call for check that not a second version can be created
            response = self.client.post(self.ok_path, content_type='application/json', HTTP_X_CSRFTOKEN=csrf_token)
            self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_400_draft(self):
        if self.execute:
            # authenticate
            self.prerequisites.auth(self.client)
            # get csrf
            csrf_token = self.prerequisites.get_csrf(self.client)
            # get API response
            response = self.client.post(self.fail_path_draft, content_type='application/json',
                                        HTTP_X_CSRFTOKEN=csrf_token)
            self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_400_circulation(self):
        if self.execute:
            # authenticate
            self.prerequisites.auth(self.client)
            # get csrf
            csrf_token = self.prerequisites.get_csrf(self.client)
            # get API response
            response = self.client.post(self.fail_path_circulation, content_type='application/json',
                                        HTTP_X_CSRFTOKEN=csrf_token)
            self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


# delete
class DeleteOne(APITestCase):
    def __init__(self, *args, **kwargs):
        super(DeleteOne, self).__init__(*args, **kwargs)

        # placeholders
        self.base_path = None
        self.model = None
        self.serializer = None
        self.ok_object_data = None
        self.prerequisites = None
        self.pre_data = None

        # flag for execution
        self.execute = False
        self.rtd = False

    def setUp(self):
        if self.execute:
            self.client = Client(enforce_csrf_checks=True)
            self.prerequisites.role_superuser()
            self.prerequisites.role_superuser_two()
            self.prerequisites.role_no_write_permissions()
            # create ok object in status draft
            if self.pre_data:
                for record in self.pre_data:
                    if record['status']:
                        self.prerequisites.create_record_manual_status(self.client, record['data'], record['path'])
                    else:
                        self.prerequisites.create_record_manual(self.client, record['data'], record['path'])
            self.ok_object = self.prerequisites.create_record(self.client, self.ok_object_data)
            # create ok path
            if self.rtd:
                self.ok_path = '{}/{}'.format(self.base_path, self.ok_object['number'])
                self.query = {'number': self.ok_object['number']}
                self.false_path_uuid = '{}/{}'.format(self.base_path, '1231231233')
            else:
                self.ok_path = '{}/{}/{}'.format(self.base_path, self.ok_object['lifecycle_id'],
                                                 self.ok_object['version'])
                self.query = {'lifecycle_id': self.ok_object['lifecycle_id'],
                              'version': self.ok_object['version']}
                self.false_path_version = '{}/{}/{}'.format(self.base_path, self.ok_object['lifecycle_id'], 2)
                self.false_path_uuid = '{}/{}/{}'.format(self.base_path, 'cac8d0f0-ce96-421c-9327-a44e4703d26f',
                                                         self.ok_object['version'])
                self.false_path_both = '{}/{}/{}'.format(self.base_path, 'cac8d0f0-ce96-421c-9327-a44e4703d26f', 2)

    def test_401(self):
        if self.execute:
            # reset auth
            self.client.logout()
            # get API response
            response = self.client.delete(self.ok_path, content_type='application/json')
            self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_403_csrf(self):
        if self.execute:
            # authenticate
            self.prerequisites.auth(self.client)
            # get API response
            response = self.client.delete(self.ok_path, content_type='application/json')
            self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_403_permission(self):
        if self.execute:
            # authenticate
            self.prerequisites.auth_no_write_perms(self.client)
            # get csrf
            csrf_token = self.prerequisites.get_csrf(self.client)
            # get API response
            response = self.client.delete(self.ok_path, content_type='application/json', HTTP_X_CSRFTOKEN=csrf_token)
            self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_404_both(self):
        if self.execute and not self.rtd:
            # authenticate
            self.prerequisites.auth(self.client)
            # get csrf
            csrf_token = self.prerequisites.get_csrf(self.client)
            # get API response
            response = self.client.delete(self.false_path_both, content_type='application/json',
                                          HTTP_X_CSRFTOKEN=csrf_token)
            self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_404_version(self):
        if self.execute and not self.rtd:
            # authenticate
            self.prerequisites.auth(self.client)
            # get csrf
            csrf_token = self.prerequisites.get_csrf(self.client)
            # get API response
            response = self.client.delete(self.false_path_version, content_type='application/json',
                                          HTTP_X_CSRFTOKEN=csrf_token)
            self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_404_uuid(self):
        if self.execute:
            # authenticate
            self.prerequisites.auth(self.client)
            # get csrf
            csrf_token = self.prerequisites.get_csrf(self.client)
            # get API response
            response = self.client.delete(self.false_path_uuid, content_type='application/json',
                                          HTTP_X_CSRFTOKEN=csrf_token)
            self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_204(self):
        if self.execute:
            # authenticate
            self.prerequisites.auth(self.client)
            # get csrf
            csrf_token = self.prerequisites.get_csrf(self.client)
            # get API response
            response = self.client.delete(self.ok_path, content_type='application/json',
                                          HTTP_X_CSRFTOKEN=csrf_token)
            self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
            # verify that role is deleted
            try:
                self.model.objects.get(**self.query)
                raise AssertionError('Object not deleted.')
            except self.model.DoesNotExist:
                pass
            # verify log record
            self.assertEqual(log_records(model=self.model, data=self.ok_object, action=settings.DEFAULT_LOG_DELETE),
                             True)

    # FO-121: new test to verify user cannot proceed when blocked
    def test_401_blocked(self):
        if self.execute and not self.rtd:
            # authenticate
            self.prerequisites.auth(self.client)
            # get csrf
            csrf_token = self.prerequisites.get_csrf(self.client)
            # block authenticated user
            self.prerequisites.block_auth_user(self.client)
            # get API response
            response = self.client.delete(self.ok_path, content_type='application/json', HTTP_X_CSRFTOKEN=csrf_token)
            self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    # FO-121: new test to verify user cannot proceed when not valid anymore
    def test_401_invalid(self):
        if self.execute and not self.rtd:
            # authenticate
            self.prerequisites.auth(self.client)
            # block authenticated user
            csrf_token = self.prerequisites.invalid_auth_user(self.client)
            # get API response
            response = self.client.delete(self.ok_path, content_type='application/json', HTTP_X_CSRFTOKEN=csrf_token)
            self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_400_circulation(self):
        if self.execute and not self.rtd:
            # authenticate
            self.prerequisites.auth(self.client)
            # get csrf
            csrf_token = self.prerequisites.get_csrf(self.client)
            # try in status circulation
            response = self.client.patch('{}/{}'.format(self.ok_path, 'circulation'), content_type='application/json',
                                         HTTP_X_CSRFTOKEN=csrf_token)
            self.assertEqual(response.data['status'], 'circulation')
            # get API response
            response = self.client.delete(self.ok_path, content_type='application/json', HTTP_X_CSRFTOKEN=csrf_token)
            self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_400_productive(self):
        if self.execute and not self.rtd:
            # authenticate
            self.prerequisites.auth(self.client)
            # get csrf
            csrf_token = self.prerequisites.get_csrf(self.client)
            self.client.patch('{}/{}'.format(self.ok_path, 'circulation'), content_type='application/json',
                              HTTP_X_CSRFTOKEN=csrf_token)
            # auth with second user to avoid SoD
            self.prerequisites.auth_two(self.client)
            # get csrf
            csrf_token = self.prerequisites.get_csrf(self.client)
            # try in status productive
            response = self.client.patch('{}/{}'.format(self.ok_path, 'productive'), content_type='application/json',
                                         HTTP_X_CSRFTOKEN=csrf_token)
            self.assertEqual(response.data['status'], 'productive')
            # get API response
            response = self.client.delete(self.ok_path, content_type='application/json', HTTP_X_CSRFTOKEN=csrf_token)
            self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_400_blocked(self):
        if self.execute and not self.rtd:
            # authenticate
            self.prerequisites.auth(self.client)
            # get csrf
            csrf_token = self.prerequisites.get_csrf(self.client)
            self.client.patch('{}/{}'.format(self.ok_path, 'circulation'), content_type='application/json',
                              HTTP_X_CSRFTOKEN=csrf_token)
            # auth with second user to avoid SoD
            self.prerequisites.auth_two(self.client)
            # get csrf
            csrf_token = self.prerequisites.get_csrf(self.client)
            self.client.patch('{}/{}'.format(self.ok_path, 'productive'), content_type='application/json',
                              HTTP_X_CSRFTOKEN=csrf_token)
            # try in status blocked
            response = self.client.patch('{}/{}'.format(self.ok_path, 'blocked'), content_type='application/json',
                                         HTTP_X_CSRFTOKEN=csrf_token)
            self.assertEqual(response.data['status'], 'blocked')
            # get API response
            response = self.client.delete(self.ok_path, content_type='application/json', HTTP_X_CSRFTOKEN=csrf_token)
            self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_400_inactive(self):
        if self.execute and not self.rtd:
            # authenticate
            self.prerequisites.auth(self.client)
            # get csrf
            csrf_token = self.prerequisites.get_csrf(self.client)
            self.client.patch('{}/{}'.format(self.ok_path, 'circulation'), content_type='application/json',
                              HTTP_X_CSRFTOKEN=csrf_token)
            # auth with second user to avoid SoD
            self.prerequisites.auth_two(self.client)
            # get csrf
            csrf_token = self.prerequisites.get_csrf(self.client)
            self.client.patch('{}/{}'.format(self.ok_path, 'productive'), content_type='application/json',
                              HTTP_X_CSRFTOKEN=csrf_token)
            # try in status blocked
            response = self.client.patch('{}/{}'.format(self.ok_path, 'inactive'), content_type='application/json',
                                         HTTP_X_CSRFTOKEN=csrf_token)
            self.assertEqual(response.data['status'], 'inactive')
            # get API response
            response = self.client.delete(self.ok_path, content_type='application/json', HTTP_X_CSRFTOKEN=csrf_token)
            self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_400_archived(self):
        if self.execute and not self.rtd:
            # authenticate
            self.prerequisites.auth(self.client)
            # get csrf
            csrf_token = self.prerequisites.get_csrf(self.client)
            self.client.patch('{}/{}'.format(self.ok_path, 'circulation'), content_type='application/json',
                              HTTP_X_CSRFTOKEN=csrf_token)
            # auth with second user to avoid SoD
            self.prerequisites.auth_two(self.client)
            # get csrf
            csrf_token = self.prerequisites.get_csrf(self.client)
            self.client.patch('{}/{}'.format(self.ok_path, 'productive'), content_type='application/json',
                              HTTP_X_CSRFTOKEN=csrf_token)
            # try in status blocked
            response = self.client.patch('{}/{}'.format(self.ok_path, 'archived'), content_type='application/json',
                                         HTTP_X_CSRFTOKEN=csrf_token)
            self.assertEqual(response.data['status'], 'archived')
            # get API response
            response = self.client.delete(self.ok_path, content_type='application/json', HTTP_X_CSRFTOKEN=csrf_token)
            self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


class DeleteOneNoStatus(APITestCase):
    def __init__(self, *args, **kwargs):
        super(DeleteOneNoStatus, self).__init__(*args, **kwargs)

        # placeholders
        self.base_path = None
        self.model = None
        self.serializer = None
        self.ok_object_data = None
        self.ok_object_data_unique = str()
        self.prerequisites = None
        self.pre_data = None

        # flag for execution
        self.execute = False

    def setUp(self):
        if self.execute:
            self.client = Client(enforce_csrf_checks=True)
            self.prerequisites.role_superuser()
            self.prerequisites.role_superuser_two()
            self.prerequisites.role_no_write_permissions()
            if self.pre_data:
                for record in self.pre_data:
                    self.prerequisites.create_record_manual(self.client, record['data'], record['path'])
            # create ok object in status draft
            self.ok_object = self.prerequisites.create_record(self.client, self.ok_object_data)
            # create ok path
            self.ok_path = '{}/{}'.format(self.base_path, self.ok_object[self.ok_object_data_unique])
            self.false_path = '{}/{}'.format(self.base_path, 'sadasuidhasdas')
            self.query = {self.ok_object_data_unique: self.ok_object[self.ok_object_data_unique]}

    def test_401(self):
        if self.execute:
            # reset auth
            self.client.logout()
            # get API response
            response = self.client.delete(self.ok_path, content_type='application/json')
            self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_403_csrf(self):
        if self.execute:
            # authenticate
            self.prerequisites.auth(self.client)
            # get API response
            response = self.client.delete(self.ok_path, content_type='application/json')
            self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_403_permission(self):
        if self.execute:
            # authenticate
            self.prerequisites.auth_no_write_perms(self.client)
            # get csrf
            csrf_token = self.prerequisites.get_csrf(self.client)
            # get API response
            response = self.client.delete(self.ok_path, content_type='application/json', HTTP_X_CSRFTOKEN=csrf_token)
            self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_404(self):
        if self.execute:
            # authenticate
            self.prerequisites.auth(self.client)
            # get csrf
            csrf_token = self.prerequisites.get_csrf(self.client)
            # get API response
            response = self.client.delete(self.false_path, content_type='application/json', HTTP_X_CSRFTOKEN=csrf_token)
            self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_204(self):
        if self.execute:
            # authenticate
            self.prerequisites.auth(self.client)
            # get csrf
            csrf_token = self.prerequisites.get_csrf(self.client)
            # get API response
            response = self.client.delete(self.ok_path, content_type='application/json',
                                          HTTP_X_CSRFTOKEN=csrf_token)
            self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
            # verify that role is deleted
            try:
                self.model.objects.get(**self.query)
                raise AssertionError('Object not deleted.')
            except self.model.DoesNotExist:
                pass
            # verify log record
            self.assertEqual(log_records(model=self.model, data=self.ok_object, action=settings.DEFAULT_LOG_DELETE,
                                         _status=False), True)

    # FO-121: new test to verify user cannot proceed when blocked
    def test_401_blocked(self):
        if self.execute:
            # authenticate
            self.prerequisites.auth(self.client)
            # get csrf
            csrf_token = self.prerequisites.get_csrf(self.client)
            # block authenticated user
            self.prerequisites.block_auth_user(self.client)
            # get API response
            response = self.client.delete(self.ok_path, content_type='application/json', HTTP_X_CSRFTOKEN=csrf_token)
            self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    # FO-121: new test to verify user cannot proceed when not valid anymore
    def test_401_invalid(self):
        if self.execute:
            # authenticate
            self.prerequisites.auth(self.client)
            # block authenticated user
            csrf_token = self.prerequisites.invalid_auth_user(self.client)
            # get API response
            response = self.client.delete(self.ok_path, content_type='application/json', HTTP_X_CSRFTOKEN=csrf_token)
            self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


# patch
class PatchOne(APITestCase):
    def __init__(self, *args, **kwargs):
        super(PatchOne, self).__init__(*args, **kwargs)

        # placeholders
        self.base_path = None
        self.model = None
        self.serializer = None
        self.ok_object_data = None
        self.prerequisites = None
        self.valid_payload = None
        self.invalid_payload = None
        self.unique_invalid_payload = None
        self.pre_data = None

        # flag for execution
        self.execute = False

    def setUp(self):
        if self.execute:
            self.client = Client(enforce_csrf_checks=True)
            self.prerequisites.role_superuser()
            self.prerequisites.role_superuser_two()
            self.prerequisites.role_no_write_permissions()
            # create ok object in status draft
            if self.pre_data:
                for record in self.pre_data:
                    if record['status']:
                        self.prerequisites.create_record_manual_status(self.client, record['data'], record['path'])
                    else:
                        self.prerequisites.create_record_manual(self.client, record['data'], record['path'])
            self.ok_object = self.prerequisites.create_record(self.client, self.ok_object_data)
            # create ok path
            self.ok_path = '{}/{}/{}'.format(self.base_path, self.ok_object['lifecycle_id'], self.ok_object['version'])
            self.query = {'lifecycle_id': self.ok_object['lifecycle_id'],
                          'version': self.ok_object['version']}

            self.false_path_version = '{}/{}/{}'.format(self.base_path, self.ok_object['lifecycle_id'], 2)
            self.false_path_uuid = '{}/{}/{}'.format(self.base_path, 'cac8d0f0-ce96-421c-9327-a44e4703d26f',
                                                     self.ok_object['version'])
            self.false_path_both = '{}/{}/{}'.format(self.base_path, 'cac8d0f0-ce96-421c-9327-a44e4703d26f', 2)

    def test_401(self):
        if self.execute:
            # reset auth
            self.client.logout()
            # get API response
            response = self.client.patch(self.ok_path, content_type='application/json')
            self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_403_csrf(self):
        if self.execute:
            # authenticate
            self.prerequisites.auth(self.client)
            # get API response
            response = self.client.patch(self.ok_path, content_type='application/json')
            self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_403_permission(self):
        if self.execute:
            # authenticate
            self.prerequisites.auth_no_write_perms(self.client)
            # get csrf
            csrf_token = self.prerequisites.get_csrf(self.client)
            # get API response
            response = self.client.patch(self.ok_path, content_type='application/json', HTTP_X_CSRFTOKEN=csrf_token)
            self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_404_both(self):
        if self.execute:
            # authenticate
            self.prerequisites.auth(self.client)
            # get csrf
            csrf_token = self.prerequisites.get_csrf(self.client)
            # get API response
            response = self.client.patch(self.false_path_both, content_type='application/json',
                                         HTTP_X_CSRFTOKEN=csrf_token)
            self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_404_version(self):
        if self.execute:
            # authenticate
            self.prerequisites.auth(self.client)
            # get csrf
            csrf_token = self.prerequisites.get_csrf(self.client)
            # get API response
            response = self.client.patch(self.false_path_version, content_type='application/json',
                                         HTTP_X_CSRFTOKEN=csrf_token)
            self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_404_uuid(self):
        if self.execute:
            # authenticate
            self.prerequisites.auth(self.client)
            # get csrf
            csrf_token = self.prerequisites.get_csrf(self.client)
            # get API response
            response = self.client.patch(self.false_path_uuid, content_type='application/json',
                                         HTTP_X_CSRFTOKEN=csrf_token)
            self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_400_circulation(self):
        if self.execute:
            # authenticate
            self.prerequisites.auth(self.client)
            # get csrf
            csrf_token = self.prerequisites.get_csrf(self.client)
            # try in status circulation
            response = self.client.patch('{}/{}'.format(self.ok_path, 'circulation'), content_type='application/json',
                                         HTTP_X_CSRFTOKEN=csrf_token)
            self.assertEqual(response.data['status'], 'circulation')
            # get API response
            response = self.client.patch(self.ok_path, data=self.valid_payload, content_type='application/json',
                                         HTTP_X_CSRFTOKEN=csrf_token)
            self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_400_productive(self):
        if self.execute:
            # authenticate
            self.prerequisites.auth(self.client)
            # get csrf
            csrf_token = self.prerequisites.get_csrf(self.client)
            self.client.patch('{}/{}'.format(self.ok_path, 'circulation'), content_type='application/json',
                              HTTP_X_CSRFTOKEN=csrf_token)
            # auth with second user to avoid SoD
            self.prerequisites.auth_two(self.client)
            # get csrf
            csrf_token = self.prerequisites.get_csrf(self.client)
            # try in status productive
            response = self.client.patch('{}/{}'.format(self.ok_path, 'productive'), content_type='application/json',
                                         HTTP_X_CSRFTOKEN=csrf_token)
            self.assertEqual(response.data['status'], 'productive')
            # get API response
            response = self.client.patch(self.ok_path, data=self.valid_payload, content_type='application/json',
                                         HTTP_X_CSRFTOKEN=csrf_token)
            self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_400_blocked(self):
        if self.execute:
            # authenticate
            self.prerequisites.auth(self.client)
            # get csrf
            csrf_token = self.prerequisites.get_csrf(self.client)
            self.client.patch('{}/{}'.format(self.ok_path, 'circulation'), content_type='application/json',
                              HTTP_X_CSRFTOKEN=csrf_token)
            # auth with second user to avoid SoD
            self.prerequisites.auth_two(self.client)
            # get csrf
            csrf_token = self.prerequisites.get_csrf(self.client)
            self.client.patch('{}/{}'.format(self.ok_path, 'productive'), content_type='application/json',
                              HTTP_X_CSRFTOKEN=csrf_token)
            # try in status blocked
            response = self.client.patch('{}/{}'.format(self.ok_path, 'blocked'), content_type='application/json',
                                         HTTP_X_CSRFTOKEN=csrf_token)
            self.assertEqual(response.data['status'], 'blocked')
            # get API response
            response = self.client.patch(self.ok_path, data=self.valid_payload, content_type='application/json',
                                         HTTP_X_CSRFTOKEN=csrf_token)
            self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_400_inactive(self):
        if self.execute:
            # authenticate
            self.prerequisites.auth(self.client)
            # get csrf
            csrf_token = self.prerequisites.get_csrf(self.client)
            self.client.patch('{}/{}'.format(self.ok_path, 'circulation'), content_type='application/json',
                              HTTP_X_CSRFTOKEN=csrf_token)
            # auth with second user to avoid SoD
            self.prerequisites.auth_two(self.client)
            # get csrf
            csrf_token = self.prerequisites.get_csrf(self.client)
            self.client.patch('{}/{}'.format(self.ok_path, 'productive'), content_type='application/json',
                              HTTP_X_CSRFTOKEN=csrf_token)
            # try in status blocked
            response = self.client.patch('{}/{}'.format(self.ok_path, 'inactive'), content_type='application/json',
                                         HTTP_X_CSRFTOKEN=csrf_token)
            self.assertEqual(response.data['status'], 'inactive')
            # get API response
            response = self.client.patch(self.ok_path, data=self.valid_payload, content_type='application/json',
                                         HTTP_X_CSRFTOKEN=csrf_token)
            self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_400_archived(self):
        if self.execute:
            # authenticate
            self.prerequisites.auth(self.client)
            # get csrf
            csrf_token = self.prerequisites.get_csrf(self.client)
            self.client.patch('{}/{}'.format(self.ok_path, 'circulation'), content_type='application/json',
                              HTTP_X_CSRFTOKEN=csrf_token)
            # auth with second user to avoid SoD
            self.prerequisites.auth_two(self.client)
            # get csrf
            csrf_token = self.prerequisites.get_csrf(self.client)
            self.client.patch('{}/{}'.format(self.ok_path, 'productive'), content_type='application/json',
                              HTTP_X_CSRFTOKEN=csrf_token)
            # try in status blocked
            response = self.client.patch('{}/{}'.format(self.ok_path, 'archived'), content_type='application/json',
                                         HTTP_X_CSRFTOKEN=csrf_token)
            self.assertEqual(response.data['status'], 'archived')
            # get API response
            response = self.client.patch(self.ok_path, data=self.valid_payload, content_type='application/json',
                                         HTTP_X_CSRFTOKEN=csrf_token)
            self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_400_data(self):
        if self.execute:
            # authenticate
            self.prerequisites.auth(self.client)
            # get csrf
            csrf_token = self.prerequisites.get_csrf(self.client)
            # get API response
            response = self.client.patch(self.ok_path, data=self.invalid_payload, content_type='application/json',
                                         HTTP_X_CSRFTOKEN=csrf_token)
            self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_200(self):
        if self.execute:
            # authenticate
            self.prerequisites.auth(self.client)
            # get csrf
            csrf_token = self.prerequisites.get_csrf(self.client)
            # get API response
            response = self.client.patch(self.ok_path, data=self.valid_payload, content_type='application/json',
                                         HTTP_X_CSRFTOKEN=csrf_token)
            query = self.model.objects.get(**self.query)
            serializer = self.serializer(query, context={'user': self.prerequisites.username})
            self.assertEqual(response.status_code, status.HTTP_200_OK)
            self.assertEqual(response.data, serializer.data)
            # verify log record
            self.assertEqual(log_records(model=self.model, data=response.data, action=settings.DEFAULT_LOG_UPDATE),
                             True)
    
    # FO-121: new test to verify user cannot proceed when blocked
    def test_401_blocked(self):
        if self.execute:
            # authenticate
            self.prerequisites.auth(self.client)
            # get csrf
            csrf_token = self.prerequisites.get_csrf(self.client)
            # block authenticated user
            self.prerequisites.block_auth_user(self.client)
            # get API response
            response = self.client.patch(self.ok_path, data=self.valid_payload, content_type='application/json',
                                         HTTP_X_CSRFTOKEN=csrf_token)
            self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    # FO-121: new test to verify user cannot proceed when not valid anymore
    def test_401_invalid(self):
        if self.execute:
            # authenticate
            self.prerequisites.auth(self.client)
            # block authenticated user
            csrf_token = self.prerequisites.invalid_auth_user(self.client)
            # get API response
            response = self.client.patch(self.ok_path, data=self.valid_payload, content_type='application/json',
                                         HTTP_X_CSRFTOKEN=csrf_token)
            self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_400_change_unique(self):
        if self.execute:
            # authenticate
            self.prerequisites.auth(self.client)
            # get csrf
            csrf_token = self.prerequisites.get_csrf(self.client)

            # start circulation
            path = '{}/{}'.format(self.ok_path, 'circulation')
            response_circ = self.client.patch(path, data=self.valid_payload, content_type='application/json',
                                              HTTP_X_CSRFTOKEN=csrf_token)
            self.assertEqual(response_circ.status_code, status.HTTP_200_OK)

            # push to productive
            # auth with second user to avoid SoD
            self.prerequisites.auth_two(self.client)
            # get csrf
            csrf_token = self.prerequisites.get_csrf(self.client)
            path = '{}/{}'.format(self.ok_path, 'productive')
            response_prod = self.client.patch(path, data=self.valid_payload, content_type='application/json',
                                              HTTP_X_CSRFTOKEN=csrf_token)
            self.assertEqual(response_prod.status_code, status.HTTP_200_OK)

            # create new version
            response = self.client.post(self.ok_path, content_type='application/json',
                                        HTTP_X_CSRFTOKEN=csrf_token)
            self.assertEqual(response.status_code, status.HTTP_201_CREATED)
            # try to change unique data
            response = self.client.patch(self.ok_path, content_type='application/json', HTTP_X_CSRFTOKEN=csrf_token,
                                         data=self.unique_invalid_payload)
            self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


class PatchOneNoStatus(APITestCase):
    def __init__(self, *args, **kwargs):
        super(PatchOneNoStatus, self).__init__(*args, **kwargs)

        # placeholders
        self.base_path = None
        self.model = None
        self.serializer = None
        self.ok_object_data = None
        self.ok_object_data_unique = str()
        self.prerequisites = None
        self.valid_payload = None
        self.invalid_payload = None
        self.data_available = False
        self.test_data = str()
        self.pre_data = None
        self.filter = {}

        # flag for execution
        self.execute = False
        self.perm_required = True

    def setUp(self):
        if self.execute:
            self.client = Client(enforce_csrf_checks=True)
            self.prerequisites.role_superuser()
            self.prerequisites.role_superuser_two()
            self.prerequisites.role_no_write_permissions()
            if self.pre_data:
                for record in self.pre_data:
                    self.prerequisites.create_record_manual(self.client, record['data'], record['path'])
            if not self.data_available:
                # create ok object in status draft
                self.ok_object = self.prerequisites.create_record(self.client, self.ok_object_data)
                # create ok path
                self.ok_path = '{}/{}'.format(self.base_path, self.ok_object[self.ok_object_data_unique])
                self.query = {self.ok_object_data_unique: self.ok_object[self.ok_object_data_unique]}
            else:
                self.ok_path = '{}/{}'.format(self.base_path, self.test_data)
                self.query = {self.ok_object_data_unique: self.test_data}
            self.false_path = '{}/{}'.format(self.base_path, 'sadasuidhasdas')

    def test_401(self):
        if self.execute:
            # reset auth
            self.client.logout()
            # get API response
            response = self.client.patch(self.ok_path, content_type='application/json')
            self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_403_csrf(self):
        if self.execute:
            # authenticate
            self.prerequisites.auth(self.client)
            # get API response
            response = self.client.patch(self.ok_path, content_type='application/json')
            self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_403_permission(self):
        if self.execute and self.perm_required:
            # authenticate
            self.prerequisites.auth_no_write_perms(self.client)
            # get csrf
            csrf_token = self.prerequisites.get_csrf(self.client)
            # get API response
            response = self.client.patch(self.ok_path, content_type='application/json', HTTP_X_CSRFTOKEN=csrf_token)
            self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_404(self):
        if self.execute:
            # authenticate
            self.prerequisites.auth(self.client)
            # get csrf
            csrf_token = self.prerequisites.get_csrf(self.client)
            # get API response
            response = self.client.patch(self.false_path, content_type='application/json', HTTP_X_CSRFTOKEN=csrf_token)
            self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_400_data(self):
        if self.execute:
            # authenticate
            self.prerequisites.auth(self.client)
            # get csrf
            csrf_token = self.prerequisites.get_csrf(self.client)
            # get API response
            response = self.client.patch(self.ok_path, data=self.invalid_payload, content_type='application/json',
                                         HTTP_X_CSRFTOKEN=csrf_token)
            self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_200(self):
        if self.execute:
            # authenticate
            self.prerequisites.auth(self.client)
            # get csrf
            csrf_token = self.prerequisites.get_csrf(self.client)
            # get API response
            response = self.client.patch(self.ok_path, data=self.valid_payload, content_type='application/json',
                                         HTTP_X_CSRFTOKEN=csrf_token)
            query = self.model.objects.filter(**self.filter).get(**self.query)
            serializer = self.serializer(query)
            self.assertEqual(response.status_code, status.HTTP_200_OK)
            self.assertEqual(response.data, serializer.data)
            # verify log record
            self.assertEqual(log_records(model=self.model, data=response.data, action=settings.DEFAULT_LOG_UPDATE,
                                         _status=False), True)
    
    # FO-121: new test to verify user cannot proceed when blocked
    def test_401_blocked(self):
        if self.execute:
            # authenticate
            self.prerequisites.auth(self.client)
            # get csrf
            csrf_token = self.prerequisites.get_csrf(self.client)
            # block authenticated user
            self.prerequisites.block_auth_user(self.client)
            # get API response
            response = self.client.patch(self.ok_path, data=self.valid_payload, content_type='application/json',
                                         HTTP_X_CSRFTOKEN=csrf_token)
            self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    # FO-121: new test to verify user cannot proceed when not valid anymore
    def test_401_invalid(self):
        if self.execute:
            # authenticate
            self.prerequisites.auth(self.client)
            # block authenticated user
            csrf_token = self.prerequisites.invalid_auth_user(self.client)
            # get API response
            response = self.client.patch(self.ok_path, data=self.valid_payload, content_type='application/json',
                                         HTTP_X_CSRFTOKEN=csrf_token)
            self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


# patch status
class PatchOneStatus(APITestCase):
    def __init__(self, *args, **kwargs):
        super(PatchOneStatus, self).__init__(*args, **kwargs)

        # placeholders
        self.base_path = None
        self.model = None
        self.serializer = None
        self.ok_object_data = None
        self.prerequisites = None
        self.pre_data = None
        self.sub_table = False

        # flag for execution
        self.execute = False
        self.rtd = False

    def status_life_cycle(self, csrf_token, _status):
        response = self.client.patch('{}/{}'.format(self.ok_path, _status), content_type='application/json',
                                     HTTP_X_CSRFTOKEN=csrf_token)
        query = self.model.objects.get(**self.query)
        serializer = self.serializer(query, context={'user': self.prerequisites.username})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data, serializer.data)
        self.assertEqual(response.data['status'], _status)
        # verify log record
        self.assertEqual(log_records(model=self.model, data=response.data, action=settings.DEFAULT_LOG_STATUS,
                                     sub_tables=self.sub_table), True)

    def setUp(self):
        if self.execute:
            self.client = Client(enforce_csrf_checks=True)
            self.prerequisites.role_superuser()
            self.prerequisites.role_superuser_two()
            self.prerequisites.role_no_write_permissions()
            # create ok object in status draft
            if self.pre_data:
                for record in self.pre_data:
                    if record['status']:
                        self.prerequisites.create_record_manual_status(self.client, record['data'], record['path'])
                    else:
                        self.prerequisites.create_record_manual(self.client, record['data'], record['path'])
            self.ok_object = self.prerequisites.create_record(self.client, self.ok_object_data)
            # create ok path
            if self.rtd:
                self.ok_path = '{}/{}'.format(self.base_path, self.ok_object['number'])
                self.query = {'number': self.ok_object['number']}
                self.false_path_uuid = '{}/{}'.format(self.base_path, '1231412341')
            else:
                self.ok_path = '{}/{}/{}'.format(self.base_path, self.ok_object['lifecycle_id'],
                                                 self.ok_object['version'])
                self.query = {'lifecycle_id': self.ok_object['lifecycle_id'],
                              'version': self.ok_object['version']}

                self.false_path_version = '{}/{}/{}'.format(self.base_path, self.ok_object['lifecycle_id'], 2)
                self.false_path_uuid = '{}/{}/{}'.format(self.base_path, 'cac8d0f0-ce96-421c-9327-a44e4703d26f',
                                                         self.ok_object['version'])
                self.false_path_both = '{}/{}/{}'.format(self.base_path, 'cac8d0f0-ce96-421c-9327-a44e4703d26f', 2)

    def test_401(self):
        if self.execute:
            # reset auth
            self.client.logout()
            # get API response
            response = self.client.patch('{}/{}'.format(self.ok_path, 'circulation'), content_type='application/json')
            self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_403_csrf(self):
        if self.execute:
            # authenticate
            self.prerequisites.auth(self.client)
            # get API response
            response = self.client.patch('{}/{}'.format(self.ok_path, 'circulation'), content_type='application/json')
            self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_403_permission(self):
        if self.execute and not self.rtd:
            # authenticate
            self.prerequisites.auth_no_write_perms(self.client)
            # get csrf
            csrf_token = self.prerequisites.get_csrf(self.client)
            # get API response
            response = self.client.patch('{}/{}'.format(self.ok_path, 'circulation'), content_type='application/json',
                                         HTTP_X_CSRFTOKEN=csrf_token)
            self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_404_both(self):
        if self.execute and not self.rtd:
            # authenticate
            self.prerequisites.auth(self.client)
            # get csrf
            csrf_token = self.prerequisites.get_csrf(self.client)
            # get API response
            response = self.client.patch('{}/{}'.format(self.false_path_both, 'circulation'),
                                         content_type='application/json', HTTP_X_CSRFTOKEN=csrf_token)
            self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_404_version(self):
        if self.execute and not self.rtd:
            # authenticate
            self.prerequisites.auth(self.client)
            # get csrf
            csrf_token = self.prerequisites.get_csrf(self.client)
            # get API response
            response = self.client.patch('{}/{}'.format(self.false_path_version, 'circulation'),
                                         content_type='application/json', HTTP_X_CSRFTOKEN=csrf_token)
            self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_404_uuid(self):
        if self.execute:
            # authenticate
            self.prerequisites.auth(self.client)
            # get csrf
            csrf_token = self.prerequisites.get_csrf(self.client)
            # get API response
            response = self.client.patch('{}/{}'.format(self.false_path_uuid, 'circulation'),
                                         content_type='application/json', HTTP_X_CSRFTOKEN=csrf_token)
            self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_400_false_status(self):
        if self.execute:
            # authenticate
            self.prerequisites.auth(self.client)
            # get csrf
            csrf_token = self.prerequisites.get_csrf(self.client)
            # get API response
            response = self.client.patch('{}/{}'.format(self.ok_path, 'false_status'), content_type='application/json',
                                         HTTP_X_CSRFTOKEN=csrf_token)
            self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_400_draft(self):
        if self.execute and not self.rtd:
            # authenticate
            self.prerequisites.auth(self.client)
            # get csrf
            csrf_token = self.prerequisites.get_csrf(self.client)
            # get API response
            not_allowed_status = ['draft', 'productive', 'blocked', 'inactive', 'archived']
            for _status in not_allowed_status:
                response = self.client.patch('{}/{}'.format(self.ok_path, _status), content_type='application/json',
                                             HTTP_X_CSRFTOKEN=csrf_token)
                self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_400_circulation(self):
        if self.execute and not self.rtd:
            # authenticate
            self.prerequisites.auth(self.client)
            # get csrf
            csrf_token = self.prerequisites.get_csrf(self.client)
            # get API response
            response = self.client.patch('{}/{}'.format(self.ok_path, 'circulation'), content_type='application/json',
                                         HTTP_X_CSRFTOKEN=csrf_token)
            self.assertEqual(response.data['status'], 'circulation')
            not_allowed_status = ['circulation', 'blocked', 'inactive', 'archived']
            for _status in not_allowed_status:
                response = self.client.patch('{}/{}'.format(self.ok_path, _status), content_type='application/json',
                                             HTTP_X_CSRFTOKEN=csrf_token)
                self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_400_productive(self):
        if self.execute and not self.rtd:
            # authenticate
            self.prerequisites.auth(self.client)
            # get csrf
            csrf_token = self.prerequisites.get_csrf(self.client)
            # get API response
            self.client.patch('{}/{}'.format(self.ok_path, 'circulation'), content_type='application/json',
                              HTTP_X_CSRFTOKEN=csrf_token)
            # auth with second user to avoid SoD
            self.prerequisites.auth_two(self.client)
            # get csrf
            csrf_token = self.prerequisites.get_csrf(self.client)
            response = self.client.patch('{}/{}'.format(self.ok_path, 'productive'), content_type='application/json',
                                         HTTP_X_CSRFTOKEN=csrf_token)
            self.assertEqual(response.data['status'], 'productive')
            not_allowed_status = ['draft', 'circulation', 'productive']
            for _status in not_allowed_status:
                response = self.client.patch('{}/{}'.format(self.ok_path, _status), content_type='application/json',
                                             HTTP_X_CSRFTOKEN=csrf_token)
                self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_400_blocked(self):
        if self.execute and not self.rtd:
            # authenticate
            self.prerequisites.auth(self.client)
            # get csrf
            csrf_token = self.prerequisites.get_csrf(self.client)
            # get API response
            self.client.patch('{}/{}'.format(self.ok_path, 'circulation'), content_type='application/json',
                              HTTP_X_CSRFTOKEN=csrf_token)
            # auth with second user to avoid SoD
            self.prerequisites.auth_two(self.client)
            # get csrf
            csrf_token = self.prerequisites.get_csrf(self.client)
            self.client.patch('{}/{}'.format(self.ok_path, 'productive'), content_type='application/json',
                              HTTP_X_CSRFTOKEN=csrf_token)
            response = self.client.patch('{}/{}'.format(self.ok_path, 'blocked'), content_type='application/json',
                                         HTTP_X_CSRFTOKEN=csrf_token)
            self.assertEqual(response.data['status'], 'blocked')
            not_allowed_status = ['draft', 'circulation', 'archived', 'inactive', 'blocked']
            for _status in not_allowed_status:
                response = self.client.patch('{}/{}'.format(self.ok_path, _status), content_type='application/json',
                                             HTTP_X_CSRFTOKEN=csrf_token)
                self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_400_archived(self):
        if self.execute and not self.rtd:
            # authenticate
            self.prerequisites.auth(self.client)
            # get csrf
            csrf_token = self.prerequisites.get_csrf(self.client)
            # get API response
            self.client.patch('{}/{}'.format(self.ok_path, 'circulation'), content_type='application/json',
                              HTTP_X_CSRFTOKEN=csrf_token)
            # auth with second user to avoid SoD
            self.prerequisites.auth_two(self.client)
            # get csrf
            csrf_token = self.prerequisites.get_csrf(self.client)
            self.client.patch('{}/{}'.format(self.ok_path, 'productive'), content_type='application/json',
                              HTTP_X_CSRFTOKEN=csrf_token)
            response = self.client.patch('{}/{}'.format(self.ok_path, 'archived'), content_type='application/json',
                                         HTTP_X_CSRFTOKEN=csrf_token)
            self.assertEqual(response.data['status'], 'archived')
            not_allowed_status = ['draft', 'circulation', 'productive', 'archived', 'inactive', 'blocked']
            for _status in not_allowed_status:
                response = self.client.patch('{}/{}'.format(self.ok_path, _status), content_type='application/json',
                                             HTTP_X_CSRFTOKEN=csrf_token)
                self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_400_inactive(self):
        if self.execute and not self.rtd:
            # authenticate
            self.prerequisites.auth(self.client)
            # get csrf
            csrf_token = self.prerequisites.get_csrf(self.client)
            # get API response
            self.client.patch('{}/{}'.format(self.ok_path, 'circulation'), content_type='application/json',
                              HTTP_X_CSRFTOKEN=csrf_token)
            # auth with second user to avoid SoD
            self.prerequisites.auth_two(self.client)
            # get csrf
            csrf_token = self.prerequisites.get_csrf(self.client)
            self.client.patch('{}/{}'.format(self.ok_path, 'productive'), content_type='application/json',
                              HTTP_X_CSRFTOKEN=csrf_token)
            response = self.client.patch('{}/{}'.format(self.ok_path, 'inactive'), content_type='application/json',
                                         HTTP_X_CSRFTOKEN=csrf_token)
            self.assertEqual(response.data['status'], 'inactive')
            not_allowed_status = ['draft', 'circulation', 'productive', 'archived', 'inactive']
            for _status in not_allowed_status:
                response = self.client.patch('{}/{}'.format(self.ok_path, _status), content_type='application/json',
                                             HTTP_X_CSRFTOKEN=csrf_token)
                self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_400_sod(self):
        if self.execute and not self.rtd:
            # authenticate
            self.prerequisites.auth(self.client)
            # get csrf
            csrf_token = self.prerequisites.get_csrf(self.client)
            # get API response
            self.client.patch('{}/{}'.format(self.ok_path, 'circulation'), content_type='application/json',
                              HTTP_X_CSRFTOKEN=csrf_token)
            # perform sod protected status change with same user
            response = self.client.patch('{}/{}'.format(self.ok_path, 'productive'), content_type='application/json',
                                         HTTP_X_CSRFTOKEN=csrf_token)
            self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_200(self):
        if self.execute and not self.rtd:
            # authenticate
            self.prerequisites.auth(self.client)
            # get csrf
            csrf_token = self.prerequisites.get_csrf(self.client)
            # get API response
            # draft to circulation
            self.status_life_cycle(csrf_token, 'circulation')
            # auth with second user to avoid SoD
            self.prerequisites.auth_two(self.client)
            # get csrf
            csrf_token = self.prerequisites.get_csrf(self.client)
            # circulation back to draft
            self.status_life_cycle(csrf_token, 'draft')
            # authenticate
            self.prerequisites.auth(self.client)
            # get csrf
            csrf_token = self.prerequisites.get_csrf(self.client)
            # start circulation again
            self.status_life_cycle(csrf_token, 'circulation')
            # auth with second user to avoid SoD
            self.prerequisites.auth_two(self.client)
            # get csrf
            csrf_token = self.prerequisites.get_csrf(self.client)
            # set productive
            self.status_life_cycle(csrf_token, 'productive')
            # block
            self.status_life_cycle(csrf_token, 'blocked')
            # back to productive
            self.status_life_cycle(csrf_token, 'productive')
            # set inactive
            self.status_life_cycle(csrf_token, 'inactive')
            # block from inactive
            self.status_life_cycle(csrf_token, 'blocked')
            # again back to productive
            self.status_life_cycle(csrf_token, 'productive')
            # finally to archive
            self.status_life_cycle(csrf_token, 'archived')
    
    # FO-121: new test to verify user cannot proceed when blocked
    def test_401_blocked(self):
        if self.execute:
            # authenticate
            self.prerequisites.auth(self.client)
            # get csrf
            csrf_token = self.prerequisites.get_csrf(self.client)
            # block authenticated user
            self.prerequisites.block_auth_user(self.client)
            # get API response
            response = self.client.patch('{}/{}'.format(self.ok_path, 'circulation'), content_type='application/json',
                                         HTTP_X_CSRFTOKEN=csrf_token)
            self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    # FO-121: new test to verify user cannot proceed when not valid anymore
    def test_401_invalid(self):
        if self.execute:
            # authenticate
            self.prerequisites.auth(self.client)
            # block authenticated user
            csrf_token = self.prerequisites.invalid_auth_user(self.client)
            # get API response
            response = self.client.patch('{}/{}'.format(self.ok_path, 'circulation'), content_type='application/json', 
                                         HTTP_X_CSRFTOKEN=csrf_token)
            self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_400_created(self):
        if self.execute and self.rtd:
            # authenticate
            self.prerequisites.auth(self.client)
            # get csrf
            csrf_token = self.prerequisites.get_csrf(self.client)
            # get API response
            not_allowed_status = ['created', 'canceled', 'complete']
            for _status in not_allowed_status:
                response = self.client.patch('{}/{}'.format(self.ok_path, _status), content_type='application/json',
                                             HTTP_X_CSRFTOKEN=csrf_token)
                self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_400_started(self):
        if self.execute and self.rtd:
            # authenticate
            self.prerequisites.auth(self.client)
            # get csrf
            csrf_token = self.prerequisites.get_csrf(self.client)
            # get API response
            response = self.client.patch('{}/{}'.format(self.ok_path, 'started'), content_type='application/json',
                                         HTTP_X_CSRFTOKEN=csrf_token)
            self.assertEqual(response.data['status'], 'started')
            not_allowed_status = ['created', 'started']
            for _status in not_allowed_status:
                response = self.client.patch('{}/{}'.format(self.ok_path, _status), content_type='application/json',
                                             HTTP_X_CSRFTOKEN=csrf_token)
                self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_400_canceled(self):
        if self.execute and self.rtd:
            # authenticate
            self.prerequisites.auth(self.client)
            # get csrf
            csrf_token = self.prerequisites.get_csrf(self.client)
            # get API response
            response = self.client.patch('{}/{}'.format(self.ok_path, 'started'), content_type='application/json',
                                         HTTP_X_CSRFTOKEN=csrf_token)
            self.assertEqual(response.data['status'], 'started')
            response = self.client.patch('{}/{}'.format(self.ok_path, 'canceled'), content_type='application/json',
                                         HTTP_X_CSRFTOKEN=csrf_token)
            self.assertEqual(response.data['status'], 'canceled')
            not_allowed_status = ['created', 'started', 'canceled', 'complete']
            for _status in not_allowed_status:
                response = self.client.patch('{}/{}'.format(self.ok_path, _status), content_type='application/json',
                                             HTTP_X_CSRFTOKEN=csrf_token)
                self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_400_complete(self):
        if self.execute and self.rtd:
            # authenticate
            self.prerequisites.auth(self.client)
            # get csrf
            csrf_token = self.prerequisites.get_csrf(self.client)
            # get API response
            response = self.client.patch('{}/{}'.format(self.ok_path, 'started'), content_type='application/json',
                                         HTTP_X_CSRFTOKEN=csrf_token)
            self.assertEqual(response.data['status'], 'started')
            response = self.client.patch('{}/{}'.format(self.ok_path, 'complete'), content_type='application/json',
                                         HTTP_X_CSRFTOKEN=csrf_token)
            self.assertEqual(response.data['status'], 'complete')
            not_allowed_status = ['created', 'started', 'canceled', 'complete']
            for _status in not_allowed_status:
                response = self.client.patch('{}/{}'.format(self.ok_path, _status), content_type='application/json',
                                             HTTP_X_CSRFTOKEN=csrf_token)
                self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
