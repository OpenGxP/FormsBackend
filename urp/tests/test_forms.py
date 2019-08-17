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
from urp.models.forms import Forms
from urp.serializers.forms import FormsReadWriteSerializer

# test imports
from urp.tests import Prerequisites, GetAll, PostNew, GetOne, PostNewVersion, DeleteOne, PatchOne, PatchOneStatus


BASE_PATH = reverse('forms-list')


###############
# /md/forms/ #
###############

# get
class GetAllForms(GetAll):
    def __init__(self, *args, **kwargs):
        super(GetAllForms, self).__init__(*args, **kwargs)
        self.base_path = BASE_PATH
        self.model = Forms
        self.serializer = FormsReadWriteSerializer
        self.execute = True


# post
class PostNewForm(PostNew):
    def __init__(self, *args, **kwargs):
        super(PostNewForm, self).__init__(*args, **kwargs)
        self.base_path = BASE_PATH
        self.model = Forms
        self.prerequisites = Prerequisites(base_path=self.base_path)
        self.valid_payload = {'form': 'test',
                              'workflow': 'myworkflow',
                              'tag': 'mytag'}
        self.invalid_payloads = [dict(),
                                 {'form': ''}]
        self.execute = True
        self.pre_data = [{'data': {'tag': 'mytag'},
                          'path': reverse('tags-list'),
                          'status': False},
                         {'data': {'workflow': 'myworkflow',
                                   'tag': 'mytag',
                                   'steps': [{'step': 'one', 'role': 'all', 'sequence': 0},
                                             {'step': 'two', 'role': 'all', 'sequence': 1, 'predecessors': ['one']}]},
                          'path': reverse('workflows-list'),
                          'status': True}]


#######################################
# /md/forms/{lifecycle_id}/{version}/ #
#######################################

# get
class GetOneForm(GetOne):
    def __init__(self, *args, **kwargs):
        super(GetOneForm, self).__init__(*args, **kwargs)
        self.base_path = BASE_PATH
        self.model = Forms
        self.prerequisites = Prerequisites(base_path=self.base_path)
        self.serializer = FormsReadWriteSerializer
        self.ok_object_data = {'form': 'test',
                               'workflow': 'myworkflow',
                               'tag': 'mytag'}
        self.execute = True
        self.pre_data = [{'data': {'tag': 'mytag'},
                          'path': reverse('tags-list'),
                          'status': False},
                         {'data': {'workflow': 'myworkflow',
                                   'tag': 'mytag',
                                   'steps': [{'step': 'one', 'role': 'all', 'sequence': 0},
                                             {'step': 'two', 'role': 'all', 'sequence': 1, 'predecessors': ['one']}]},
                          'path': reverse('workflows-list'),
                          'status': True}]


# post
class PostNewVersionForm(PostNewVersion):
    def __init__(self, *args, **kwargs):
        super(PostNewVersionForm, self).__init__(*args, **kwargs)
        self.base_path = BASE_PATH
        self.model = Forms
        self.prerequisites = Prerequisites(base_path=self.base_path)
        self.serializer = FormsReadWriteSerializer
        self.ok_object_data = {'form': 'test',
                               'workflow': 'myworkflow',
                               'tag': 'mytag'}
        self.fail_object_draft_data = {'form': 'test_draft',
                                       'workflow': 'myworkflow',
                                       'tag': 'mytag'}
        self.fail_object_circulation_data = {'form': 'test_circ',
                                             'workflow': 'myworkflow',
                                             'tag': 'mytag'}
        self.execute = True
        self.pre_data = [{'data': {'tag': 'mytag'},
                          'path': reverse('tags-list'),
                          'status': False},
                         {'data': {'workflow': 'myworkflow',
                                   'tag': 'mytag',
                                   'steps': [{'step': 'one', 'role': 'all', 'sequence': 0},
                                             {'step': 'two', 'role': 'all', 'sequence': 1, 'predecessors': ['one']}]},
                          'path': reverse('workflows-list'),
                          'status': True}]


# delete
class DeleteOneForm(DeleteOne):
    def __init__(self, *args, **kwargs):
        super(DeleteOneForm, self).__init__(*args, **kwargs)
        self.base_path = BASE_PATH
        self.model = Forms
        self.prerequisites = Prerequisites(base_path=self.base_path)
        self.serializer = FormsReadWriteSerializer
        self.ok_object_data = {'form': 'test',
                               'workflow': 'myworkflow',
                               'tag': 'mytag'}
        self.execute = True
        self.pre_data = [{'data': {'tag': 'mytag'},
                          'path': reverse('tags-list'),
                          'status': False},
                         {'data': {'workflow': 'myworkflow',
                                   'tag': 'mytag',
                                   'steps': [{'step': 'one', 'role': 'all', 'sequence': 0},
                                             {'step': 'two', 'role': 'all', 'sequence': 1, 'predecessors': ['one']}]},
                          'path': reverse('workflows-list'),
                          'status': True}]


# patch
class PatchOneForm(PatchOne):
    def __init__(self, *args, **kwargs):
        super(PatchOneForm, self).__init__(*args, **kwargs)
        self.base_path = BASE_PATH
        self.model = Forms
        self.prerequisites = Prerequisites(base_path=self.base_path)
        self.serializer = FormsReadWriteSerializer
        self.ok_object_data = {'form': 'test',
                               'workflow': 'myworkflow',
                               'tag': 'mytag'}
        self.valid_payload = {'form': 'test',
                              'workflow': 'myworkflow',
                              'tag': 'mytagneu'}
        self.invalid_payload = {'form': 'test',
                                'workflow': 'myworkflowdddd',
                                'tag': 'mytag'}
        self.unique_invalid_payload = {'form': 'testneu',
                                       'workflow': 'myworkflow',
                                       'tag': 'mytag'}
        self.execute = True
        self.pre_data = [{'data': {'tag': 'mytag'},
                          'path': reverse('tags-list'),
                          'status': False},
                         {'data': {'tag': 'mytagneu'},
                          'path': reverse('tags-list'),
                          'status': False},
                         {'data': {'workflow': 'myworkflow',
                                   'tag': 'mytag',
                                   'steps': [{'step': 'one', 'role': 'all', 'sequence': 0},
                                             {'step': 'two', 'role': 'all', 'sequence': 1, 'predecessors': ['one']}]},
                          'path': reverse('workflows-list'),
                          'status': True}]


###################################################
# /md/forms/{lifecycle_id}/{version}/{status} #
###################################################

# patch
class PatchOneStatusForm(PatchOneStatus):
    def __init__(self, *args, **kwargs):
        super(PatchOneStatusForm, self).__init__(*args, **kwargs)
        self.base_path = BASE_PATH
        self.model = Forms
        self.prerequisites = Prerequisites(base_path=self.base_path)
        self.serializer = FormsReadWriteSerializer
        self.ok_object_data = {'form': 'test',
                               'workflow': 'myworkflow',
                               'tag': 'mytag'}
        self.execute = True
        self.pre_data = [{'data': {'tag': 'mytag'},
                          'path': reverse('tags-list'),
                          'status': False},
                         {'data': {'workflow': 'myworkflow',
                                   'tag': 'mytag',
                                   'steps': [{'step': 'one', 'role': 'all', 'sequence': 0},
                                             {'step': 'two', 'role': 'all', 'sequence': 1, 'predecessors': ['one']}]},
                          'path': reverse('workflows-list'),
                          'status': True}]
