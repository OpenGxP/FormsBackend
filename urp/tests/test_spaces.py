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

# app imports
from ..models import Spaces
from ..serializers import SpacesReadWriteSerializer

# test imports
from . import Prerequisites, GetAll, PostNew, DeleteOneNoStatus, PatchOneNoStatus, GetOneNoStatus


BASE_PATH = reverse('spaces-list')


##################
# /admin/spaces/ #
##################

# get
class GetAllSpaces(GetAll):
    def __init__(self, *args, **kwargs):
        super(GetAllSpaces, self).__init__(*args, **kwargs)
        self.base_path = BASE_PATH
        self.model = Spaces
        self.serializer = SpacesReadWriteSerializer
        self.execute = True


class GetOneNoStatusSpaces(GetOneNoStatus):
    def __init__(self, *args, **kwargs):
        super(GetOneNoStatusSpaces, self).__init__(*args, **kwargs)
        self.base_path = BASE_PATH
        self.prerequisites = Prerequisites(base_path=self.base_path)

        self.model = Spaces
        self.serializer = SpacesReadWriteSerializer
        self.execute = True
        self.ok_object_data = {'space': 'all',
                               'tags': ['all', 'two'],
                               'users': ['superuser']}
        self.ok_object_data_unique = 'space'
        self.pre_data = [{'data': {'tag': 'all'},
                          'path': reverse('tags-list')},
                         {'data': {'tag': 'two'},
                          'path': reverse('tags-list')}]


# post
class PostNewSpaces(PostNew):
    def __init__(self, *args, **kwargs):
        super(PostNewSpaces, self).__init__(*args, **kwargs)
        self.base_path = BASE_PATH
        self.model = Spaces
        self.prerequisites = Prerequisites(base_path=self.base_path)
        self.valid_payload = {'space': 'all',
                              'tags': ['all,two'],
                              'users': ['superuser']}
        invalid_payload = {'space': ''}
        self.invalid_payloads = [dict(),
                                 invalid_payload,
                                 {'space': 'all1234',
                                  'tags': ['all,qc,ops']},
                                 {'space': 'all222222d',
                                  'tags': [],
                                  'users': ['userone,usertwo']}]
        self.pre_data = [{'data': {'tag': 'all'},
                          'path': reverse('tags-list')},
                         {'data': {'tag': 'two'},
                          'path': reverse('tags-list')}]
        self.execute = True
        self.status = False


# delete
class DeleteOneSpaces(DeleteOneNoStatus):
    def __init__(self, *args, **kwargs):
        super(DeleteOneSpaces, self).__init__(*args, **kwargs)
        self.base_path = BASE_PATH
        self.model = Spaces
        self.prerequisites = Prerequisites(base_path=self.base_path)
        self.serializer = SpacesReadWriteSerializer
        self.ok_object_data = {'space': 'all',
                               'tags': ['all,two'],
                               'users': ['superuser']}
        self.pre_data = [{'data': {'tag': 'all'},
                          'path': reverse('tags-list')},
                         {'data': {'tag': 'two'},
                          'path': reverse('tags-list')}]
        self.ok_object_data_unique = 'space'
        self.execute = True


# patch
class PatchOneSpaces(PatchOneNoStatus):
    def __init__(self, *args, **kwargs):
        super(PatchOneSpaces, self).__init__(*args, **kwargs)
        self.base_path = BASE_PATH
        self.model = Spaces
        self.prerequisites = Prerequisites(base_path=self.base_path)
        self.serializer = SpacesReadWriteSerializer
        self.ok_object_data_unique = 'space'
        self.ok_object_data = {'space': 'all',
                               'tags': ['all,two'],
                               'users': ['superuser']}
        self.valid_payload = {'space': 'all',
                              'tags': ['all'],
                              'users': ['superuser']}
        self.pre_data = [{'data': {'tag': 'all'},
                          'path': reverse('tags-list')},
                         {'data': {'tag': 'two'},
                          'path': reverse('tags-list')}]
        self.invalid_payload = {'space': ''}
        self.execute = True
