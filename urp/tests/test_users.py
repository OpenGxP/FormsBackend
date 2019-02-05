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
from . import Prerequisites, GetAll, GetOne, PostNew


###########
# /users/ #
###########

# get
class GetAllUsers(GetAll):
    def __init__(self, *args, **kwargs):
        super(GetAllUsers, self).__init__(*args, **kwargs)
        self.base_path = reverse('users-list')
        self.model = Users
        self.serializer = UsersReadSerializer
        self.execute = True


# post
class PostNewUsers(PostNew):
    def __init__(self, *args, **kwargs):
        super(PostNewUsers, self).__init__(*args, **kwargs)
        self.base_path = reverse('users-list')
        self.model = Users
        self.prerequisites = Prerequisites(base_path=self.base_path)
        self.valid_payload = {'first_name': 'peter',
                              'last_name': 'pan',
                              'password': 'test12345test',
                              'roles': 'all',
                              'valid_from': timezone.now()}
        self.invalid_payloads = [dict(),
                                 {'first_name': '',
                                  'last_name': 'pan',
                                  'password': 'test12345test',
                                  'roles': 'all',
                                  'valid_from': timezone.now()},
                                 {'first_name': 'peter',
                                  'last_name': '',
                                  'password': 'test12345test',
                                  'roles': 'all',
                                  'valid_from': timezone.now()},
                                 {'first_name': 'peter',
                                  'last_name': 'pan',
                                  'password': '',
                                  'roles': 'all',
                                  'valid_from': timezone.now()},
                                 {'first_name': 'peter',
                                  'last_name': 'pan',
                                  'password': 'test12345test',
                                  'roles': '',
                                  'valid_from': timezone.now()},
                                 {'first_name': 'peter',
                                  'last_name': 'pan',
                                  'password': 'test12345test',
                                  'roles': 'all',
                                  'valid_from': ''}]
        self.execute = True


####################################
# /users/{lifecycle_id}/{version}/ #
####################################

# get
class GetOneUser(GetOne):
    def __init__(self, *args, **kwargs):
        super(GetOneUser, self).__init__(*args, **kwargs)
        self.base_path = reverse('users-list')
        self.model = Users
        self.prerequisites = Prerequisites(base_path=self.base_path)
        self.serializer = UsersReadSerializer
        self.ok_object_data = {'first_name': 'peter',
                               'last_name': 'pan',
                               'password': 'test12345test',
                               'roles': 'all',
                               'valid_from': timezone.now()}
        self.execute = True
