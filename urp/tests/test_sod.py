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
from rest_framework.test import APITestCase

# app imports
from ..models import SoD
from ..serializers import SoDReadSerializer

# test imports
from . import Prerequisites, GetAll, PostNew, GetOne, PostNewVersion, DeleteOne, PatchOne, PatchOneStatus


BASE_PATH = reverse('sod-list')


#########
# /sod/ #
#########

# get
class GetAllSoD(GetAll):
    def __init__(self, *args, **kwargs):
        super(GetAllSoD, self).__init__(*args, **kwargs)
        self.base_path = BASE_PATH
        self.model = SoD
        self.serializer = SoDReadSerializer
        self.execute = True


# post
class PostNewSoD(PostNew):
    def __init__(self, *args, **kwargs):
        super(PostNewSoD, self).__init__(*args, **kwargs)
        self.base_path = BASE_PATH
        self.model = SoD
        self.prerequisites = Prerequisites(base_path=self.base_path)
        self.valid_payload = {'base': 'test',
                              'conflict': 'test'}
        self.invalid_payloads = [dict(),
                                 {'base': ''},
                                 {'conflict': ''},
                                 {'base': 'test', 'conflict': ''},
                                 {'base': '', 'conflict': 'test'}]
        self.execute = True


##################################
# /sod/{lifecycle_id}/{version}/ #
##################################

# get
class GetOneSoD(GetOne):
    def __init__(self, *args, **kwargs):
        super(GetOneSoD, self).__init__(*args, **kwargs)
        self.base_path = BASE_PATH
        self.model = SoD
        self.prerequisites = Prerequisites(base_path=self.base_path)
        self.serializer = SoDReadSerializer
        self.ok_object_data = {'base': 'test',
                               'conflict': 'test'}
        self.execute = True


# post
class PostNewVersionSoD(PostNewVersion):
    def __init__(self, *args, **kwargs):
        super(PostNewVersionSoD, self).__init__(*args, **kwargs)
        self.base_path = BASE_PATH
        self.model = SoD
        self.prerequisites = Prerequisites(base_path=self.base_path)
        self.serializer = SoDReadSerializer
        self.ok_object_data = {'base': 'test',
                               'conflict': 'test'}
        self.fail_object_draft_data = {'base': 'test_draft',
                                       'conflict': 'test'}
        self.fail_object_circulation_data = {'base': 'test_circ',
                                             'conflict': 'test'}
        self.execute = True


# delete
class DeleteOneSoD(DeleteOne):
    def __init__(self, *args, **kwargs):
        super(DeleteOneSoD, self).__init__(*args, **kwargs)
        self.base_path = BASE_PATH
        self.model = SoD
        self.prerequisites = Prerequisites(base_path=self.base_path)
        self.serializer = SoDReadSerializer
        self.ok_object_data = {'base': 'test',
                               'conflict': 'test'}
        self.execute = True


# patch
class PatchOneSoD(PatchOne):
    def __init__(self, *args, **kwargs):
        super(PatchOneSoD, self).__init__(*args, **kwargs)
        self.base_path = BASE_PATH
        self.model = SoD
        self.prerequisites = Prerequisites(base_path=self.base_path)
        self.serializer = SoDReadSerializer
        self.ok_object_data = {'base': 'test',
                               'conflict': 'test'}
        self.valid_payload = {
            'base': 'test',
            'conflict': 'testneu'
        }
        self.invalid_payload = {
            'base': 'testeu',
            'conflict': ''
        }
        self.unique_invalid_payload = {'base': 'anders', 'conflict': 'neu'}
        self.execute = True


##########################################
# /sod/{lifecycle_id}/{version}/{status} #
##########################################

# patch
class PatchOneStatusSoD(PatchOneStatus):
    def __init__(self, *args, **kwargs):
        super(PatchOneStatusSoD, self).__init__(*args, **kwargs)
        self.base_path = BASE_PATH
        self.model = SoD
        self.prerequisites = Prerequisites(base_path=self.base_path)
        self.serializer = SoDReadSerializer
        self.ok_object_data = {'base': 'test',
                               'conflict': 'test'}
        self.execute = True


# patch
class SoDMiscellaneous(APITestCase):
    def __init__(self, *args, **kwargs):
        super(SoDMiscellaneous, self).__init__(*args, **kwargs)
        self.base_path = BASE_PATH
        self.prerequisites = Prerequisites(base_path=self.base_path)

    def setUp(self):
        self.client = Client(enforce_csrf_checks=True)
        self.prerequisites.role_superuser()
        self.prerequisites.role_superuser_two()
