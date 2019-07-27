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
from urp.models.lists import Lists
from urp.serializers import ListsReadWriteSerializer

# test imports
from urp.tests import Prerequisites, GetAll, PostNew, GetOne, PostNewVersion, DeleteOne, PatchOne, PatchOneStatus


BASE_PATH = reverse('lists-list')


##############
# /md/lists/ #
##############

# get
class GetAllLists(GetAll):
    def __init__(self, *args, **kwargs):
        super(GetAllLists, self).__init__(*args, **kwargs)
        self.base_path = BASE_PATH
        self.model = Lists
        self.serializer = ListsReadWriteSerializer
        self.execute = True


# post
class PostNewLists(PostNew):
    def __init__(self, *args, **kwargs):
        super(PostNewLists, self).__init__(*args, **kwargs)
        self.base_path = BASE_PATH
        self.model = Lists
        self.prerequisites = Prerequisites(base_path=self.base_path)
        self.valid_payload = {'list': 'test',
                              'type': 'copy',
                              'tag': 'mytag',
                              'elements': ['test1', 'test2', 'test3']}
        self.invalid_payloads = [dict(),
                                 {'list': ''},
                                 {'list': 'test',
                                  'type': 'cosspy',
                                  'tag': 'mytag',
                                  'elements': ['test1', 'test2', 'test3']},
                                 {'list': 'test',
                                  'type': 'copy',
                                  'tag': 'dasdasd',
                                  'elements': ['test1', 'test2', 'test3']},
                                 {'list': 'test',
                                  'type': 'copy',
                                  'tag': 'mytag',
                                  'elements': 'test1'}]
        self.execute = True
        self.pre_data = [{'data': {'tag': 'mytag'},
                          'path': reverse('tags-list')}]


#######################################
# /md/lists/{lifecycle_id}/{version}/ #
#######################################

# get
class GetOneList(GetOne):
    def __init__(self, *args, **kwargs):
        super(GetOneList, self).__init__(*args, **kwargs)
        self.base_path = BASE_PATH
        self.model = Lists
        self.prerequisites = Prerequisites(base_path=self.base_path)
        self.serializer = ListsReadWriteSerializer
        self.ok_object_data = {'list': 'test',
                               'type': 'copy',
                               'elements': ['test1', 'test2', 'test3']}
        self.execute = True
        self.pre_data = [{'data': {'tag': 'mytag'},
                          'path': reverse('tags-list')}]


# post
class PostNewVersionList(PostNewVersion):
    def __init__(self, *args, **kwargs):
        super(PostNewVersionList, self).__init__(*args, **kwargs)
        self.base_path = BASE_PATH
        self.model = Lists
        self.prerequisites = Prerequisites(base_path=self.base_path)
        self.serializer = ListsReadWriteSerializer
        self.ok_object_data = {'list': 'test',
                               'type': 'copy',
                               'tag': 'mytag',
                               'elements': ['test1', 'test2', 'test3']}
        self.fail_object_draft_data = {'list': 'test_draft',
                                       'type': 'copy',
                                       'tag': 'mytag',
                                       'elements': ['test1', 'test2', 'test3']}
        self.fail_object_circulation_data = {'list': 'test_circ',
                                             'type': 'copy',
                                             'tag': 'mytag',
                                             'elements': ['test1', 'test2', 'test3']}
        self.execute = True
        self.pre_data = [{'data': {'tag': 'mytag'},
                          'path': reverse('tags-list')}]


# delete
class DeleteOneList(DeleteOne):
    def __init__(self, *args, **kwargs):
        super(DeleteOneList, self).__init__(*args, **kwargs)
        self.base_path = BASE_PATH
        self.model = Lists
        self.prerequisites = Prerequisites(base_path=self.base_path)
        self.serializer = ListsReadWriteSerializer
        self.ok_object_data = {'list': 'test',
                               'type': 'copy',
                               'tag': 'mytag',
                               'elements': ['test1', 'test2', 'test3']}
        self.execute = True
        self.pre_data = [{'data': {'tag': 'mytag'},
                          'path': reverse('tags-list')}]


# patch
class PatchOneList(PatchOne):
    def __init__(self, *args, **kwargs):
        super(PatchOneList, self).__init__(*args, **kwargs)
        self.base_path = BASE_PATH
        self.model = Lists
        self.prerequisites = Prerequisites(base_path=self.base_path)
        self.serializer = ListsReadWriteSerializer
        self.ok_object_data = {'list': 'test',
                               'type': 'copy',
                               'tag': 'mytag',
                               'elements': ['test1', 'test2', 'test3']}
        self.valid_payload = {'list': 'test',
                              'type': 'reference',
                              'tag': 'mytag',
                              'elements': ['neu']}
        self.invalid_payload = {'list': '',
                                'type': 'copy',
                                'tag': 'mytag',
                                'elements': ['test1', 'test2', 'test3']}
        self.unique_invalid_payload = {'list': 'testneu',
                                       'type': 'copy',
                                       'tag': 'mytag',
                                       'elements': ['test1', 'test2', 'test3']}
        self.execute = True
        self.pre_data = [{'data': {'tag': 'mytag'},
                          'path': reverse('tags-list')}]


###############################################
# /md/lists/{lifecycle_id}/{version}/{status} #
###############################################

# patch
class PatchOneStatusList(PatchOneStatus):
    def __init__(self, *args, **kwargs):
        super(PatchOneStatusList, self).__init__(*args, **kwargs)
        self.base_path = BASE_PATH
        self.model = Lists
        self.prerequisites = Prerequisites(base_path=self.base_path)
        self.serializer = ListsReadWriteSerializer
        self.ok_object_data = {'list': 'test',
                               'type': 'copy',
                               'tag': 'mytag',
                               'elements': ['test1', 'test2', 'test3']}
        self.execute = True
        self.pre_data = [{'data': {'tag': 'mytag'},
                          'path': reverse('tags-list')}]
