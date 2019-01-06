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
from rest_framework.test import APIClient

# app imports
from ..models import Users
from ..serializers import UsersReadSerializer

# test imports
from . import Prerequisites, Get, Post


###########
# /users/ #
###########

# get
class GetUsers(Get):
    def __init__(self, *args, **kwargs):
        super(GetUsers, self).__init__(*args, **kwargs)
        self.path = reverse('users-list')
        self.model = Users
        self.serializer = UsersReadSerializer
        self.execute = True


# post
class PostUsers(Post):
    def __init__(self, *args, **kwargs):
        super(PostUsers, self).__init__(*args, **kwargs)
        self.path = reverse('roles-list')
        self.model = Users
        self.prerequisites = Prerequisites(base_path=self.path)
        self.execute = True

    def setUp(self):
        self.client = APIClient(enforce_csrf_checks=True)
        self.prerequisites.role_superuser()
        self.valid_payload = {'first_name': 'max',
                              'last_name': 'mustermann',
                              'valid_from': timezone.now(),
                              'roles': 'all'}
        self.invalid_payloads = [dict(),
                                 {'first_name': 'max',
                                  'last_name': 'mustermann',
                                  'valid_from': timezone.now()},
                                 {'first_name': 'max',
                                  'last_name': 'mustermann',
                                  'roles': 'all'},
                                 {'first_name': 'max',
                                  'valid_from': timezone.now(),
                                  'roles': 'all'},
                                 {'last_name': 'mustermann',
                                  'valid_from': timezone.now(),
                                  'roles': 'all'}]
