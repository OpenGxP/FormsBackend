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

# app imports
from ..models import Users
from ..serializers import UsersReadSerializer

# test imports
from . import Prerequisites, GetAll, GetOne, PostNew, PostNewVersion, PatchOneStatus, DeleteOne, PatchOne


BASE_PATH = reverse('users-list')


###########
# /users/ #
###########

# get
class GetAllUsers(GetAll):
    def __init__(self, *args, **kwargs):
        super(GetAllUsers, self).__init__(*args, **kwargs)
        self.base_path = BASE_PATH
        self.model = Users
        self.serializer = UsersReadSerializer
        self.execute = True


# post
class PostNewUsers(PostNew):
    def __init__(self, *args, **kwargs):
        super(PostNewUsers, self).__init__(*args, **kwargs)
        self.base_path = BASE_PATH
        self.model = Users
        self.prerequisites = Prerequisites(base_path=self.base_path)
        self.valid_payload = {'username': 'test123',
                              'password': 'test12345test',
                              'roles': 'all',
                              'valid_from': timezone.now(),
                              'ldap': False}
        self.invalid_payloads = [dict(),
                                 {'username': 'test123',
                                  'roles': 'all',
                                  'password': '',
                                  'valid_from': timezone.now()},
                                 {'username': 'test123',
                                  'password': 'test12345test',
                                  'roles': '',
                                  'valid_from': timezone.now()}]
        self.execute = True


####################################
# /users/{lifecycle_id}/{version}/ #
####################################

# get
class GetOneUser(GetOne):
    def __init__(self, *args, **kwargs):
        super(GetOneUser, self).__init__(*args, **kwargs)
        self.base_path = BASE_PATH
        self.model = Users
        self.prerequisites = Prerequisites(base_path=self.base_path)
        self.serializer = UsersReadSerializer
        self.ok_object_data = {'username': 'test123',
                               'password': 'test12345test',
                               'roles': 'all',
                               'valid_from': timezone.now(),
                               'ldap': False}
        self.execute = True


# post
class PostNewVersionUser(PostNewVersion):
    def __init__(self, *args, **kwargs):
        super(PostNewVersionUser, self).__init__(*args, **kwargs)
        self.base_path = BASE_PATH
        self.model = Users
        self.prerequisites = Prerequisites(base_path=self.base_path)
        self.serializer = UsersReadSerializer
        self.ok_object_data = {'username': 'test123',
                               'password': 'test12345test',
                               'roles': 'all',
                               'valid_from': timezone.now(),
                               'ldap': False}
        self.fail_object_draft_data = {'username': 'test123',
                                       'password': 'test12345test',
                                       'roles': 'all',
                                       'valid_from': timezone.now(),
                                       'ldap': False}
        self.fail_object_circulation_data = {'username': 'test123',
                                             'password': 'test12345test',
                                             'roles': 'all',
                                             'valid_from': timezone.now(),
                                             'ldap': False}
        self.execute = True


# delete
class DeleteOneUser(DeleteOne):
    def __init__(self, *args, **kwargs):
        super(DeleteOneUser, self).__init__(*args, **kwargs)
        self.base_path = BASE_PATH
        self.model = Users
        self.prerequisites = Prerequisites(base_path=self.base_path)
        self.serializer = UsersReadSerializer
        self.ok_object_data = {'username': 'test123',
                               'password': 'test12345test',
                               'roles': 'all',
                               'valid_from': timezone.now(),
                               'ldap': False}
        self.execute = True


# patch
class PatchOneUser(PatchOne):
    def __init__(self, *args, **kwargs):
        super(PatchOneUser, self).__init__(*args, **kwargs)
        self.base_path = BASE_PATH
        self.model = Users
        self.prerequisites = Prerequisites(base_path=self.base_path)
        self.serializer = UsersReadSerializer
        self.ok_object_data = {'username': 'test123',
                               'password': 'test12345test',
                               'roles': 'all',
                               'valid_from': timezone.now(),
                               'ldap': False}
        self.valid_payload = {'username': 'dasddasd',
                              'password': 'test12345test',
                              'roles': 'all',
                              'valid_from': timezone.now(),
                              'ldap': False}
        self.invalid_payload = {'username': '',
                                'password': 'test12345test',
                                'roles': 'all',
                                'valid_from': timezone.now(),
                                'ldap': False}
        self.execute = True


############################################
# /roles/{lifecycle_id}/{version}/{status} #
############################################

# patch
class PatchOneStatusUser(PatchOneStatus):
    def __init__(self, *args, **kwargs):
        super(PatchOneStatusUser, self).__init__(*args, **kwargs)
        self.base_path = BASE_PATH
        self.model = Users
        self.prerequisites = Prerequisites(base_path=self.base_path)
        self.serializer = UsersReadSerializer
        self.ok_object_data = {'username': 'test123',
                               'password': 'test12345test',
                               'roles': 'all',
                               'valid_from': timezone.now(),
                               'ldap': False}
        self.execute = True
