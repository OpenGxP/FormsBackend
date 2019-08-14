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
from django.test import Client

# rest framework imports
from rest_framework import status
from rest_framework.test import APITestCase

# app imports
from urp.models.profile import Profile
from urp.serializers.profile import ProfileReadWriteSerializer

# test imports
from . import Prerequisites, GetAll, PatchOneNoStatus, GetOneNoStatus


BASE_PATH = reverse('profile-list')


#############
# /profile/ #
#############

# get
class GetAllProfiles(GetAll):
    def __init__(self, *args, **kwargs):
        super(GetAllProfiles, self).__init__(*args, **kwargs)
        self.base_path = BASE_PATH
        self.model = Profile
        self.serializer = ProfileReadWriteSerializer
        self.execute = True
        self.perm_required = False
        self.filter = {'username': self.prerequisites.username}


class GetOneNoStatusProfile(GetOneNoStatus):
    def __init__(self, *args, **kwargs):
        super(GetOneNoStatusProfile, self).__init__(*args, **kwargs)
        self.base_path = BASE_PATH
        self.prerequisites = Prerequisites(base_path=self.base_path)
        self.model = Profile
        self.serializer = ProfileReadWriteSerializer
        self.execute = True
        self.perm_required = False
        self.data_available = True
        self.filter = {'username': self.prerequisites.username}
        self.ok_object_data_unique = 'key'
        self.test_data = 'loc.timezone'


# patch
class PatchOneProfile(PatchOneNoStatus):
    def __init__(self, *args, **kwargs):
        super(PatchOneProfile, self).__init__(*args, **kwargs)
        self.base_path = BASE_PATH
        self.model = Profile
        self.prerequisites = Prerequisites(base_path=self.base_path)
        self.serializer = ProfileReadWriteSerializer
        self.execute = True
        self.perm_required = False
        self.data_available = True
        self.ok_object_data_unique = 'key'
        self.test_data = 'loc.language'
        self.valid_payload = {'value': 'de_DE'}
        self.invalid_payload = {'key': 'changedkey'}
        self.filter = {'username': self.prerequisites.username}
