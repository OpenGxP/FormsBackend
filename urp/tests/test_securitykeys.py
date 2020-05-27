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

# django imports
from django.urls import reverse
from django.test import Client

# app imports
from urp.models.securitykeys import SecurityKeys
from urp.serializers.securitykeys import SecurityKeysReadWriteSerializer

# test imports
from . import Prerequisites, GetAll, PostNew, DeleteOneNoStatus, GetOneNoStatus


BASE_PATH = reverse('securitykeys-list')


# get
class GetAllSecurityKeys(GetAll):
    def __init__(self, *args, **kwargs):
        super(GetAllSecurityKeys, self).__init__(*args, **kwargs)
        self.base_path = BASE_PATH
        self.model = SecurityKeys
        self.serializer = SecurityKeysReadWriteSerializer
        self.execute = True


class GetOneNoStatusSecurityKey(GetOneNoStatus):
    def __init__(self, *args, **kwargs):
        super(GetOneNoStatusSecurityKey, self).__init__(*args, **kwargs)
        self.base_path = BASE_PATH
        self.prerequisites = Prerequisites(base_path=self.base_path)
        self.model = SecurityKeys
        self.serializer = SecurityKeysReadWriteSerializer
        self.execute = True
        self.ok_object_data = {'username': self.prerequisites.username}
        self.ok_object_data_unique = 'security_key'

    def setUp(self):
        if self.execute:
            self.client = Client()
            self.prerequisites.role_superuser()
            self.prerequisites.role_no_permissions()
            # create ok object
            self.ok_object = self.prerequisites.create_record(self.client, self.ok_object_data)
            # create ok path
            self.ok_path = '{}/{}'.format(self.base_path, self.ok_object['unique'])
            self.query = {self.ok_object_data_unique: self.ok_object['unique']}
            self.false_path = '{}/{}'.format(self.base_path, 'sadasuidhasdas')


# post
class PostNewSecurityKey(PostNew):
    def __init__(self, *args, **kwargs):
        super(PostNewSecurityKey, self).__init__(*args, **kwargs)
        self.base_path = BASE_PATH
        self.model = SecurityKeys
        self.prerequisites = Prerequisites(base_path=self.base_path)
        self.valid_payload = {'username': self.prerequisites.username}
        self.invalid_payloads = [dict(),
                                 {'username': ''},
                                 {'username': 'asdasda'}]
        self.execute = True
        self.status = False

    # do not do second test, because no real unique value, endless posts possible
    def test_400_second(self):
        pass


# delete
class DeleteOneSecurityKey(DeleteOneNoStatus):
    def __init__(self, *args, **kwargs):
        super(DeleteOneSecurityKey, self).__init__(*args, **kwargs)
        self.base_path = BASE_PATH
        self.model = SecurityKeys
        self.prerequisites = Prerequisites(base_path=self.base_path)
        self.serializer = SecurityKeysReadWriteSerializer
        self.ok_object_data = {'username': self.prerequisites.username}
        self.ok_object_data_unique = 'security_key'
        self.execute = True

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
            self.ok_path = '{}/{}'.format(self.base_path, self.ok_object['unique'])
            self.false_path = '{}/{}'.format(self.base_path, 'sadasuidhasdas')
            self.query = {self.ok_object_data_unique: self.ok_object['unique']}
