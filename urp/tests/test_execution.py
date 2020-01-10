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

# app imports
from urp.models.execution.execution import Execution
from urp.serializers.execution import ExecutionReadWriteSerializer

# test imports
from . import Prerequisites, GetAll, PostNew, GetOne, DeleteOne, PatchOneStatus


BASE_PATH = reverse('execution-list')


##################
# rdt/execution/ #
##################

# get
class GetAllExecution(GetAll):
    def __init__(self, *args, **kwargs):
        super(GetAllExecution, self).__init__(*args, **kwargs)
        self.base_path = BASE_PATH
        self.model = Execution
        self.serializer = ExecutionReadWriteSerializer
        self.execute = True


# post
class PostNewExecution(PostNew):
    def __init__(self, *args, **kwargs):
        super(PostNewExecution, self).__init__(*args, **kwargs)
        self.base_path = BASE_PATH
        self.model = Execution
        self.prerequisites = Prerequisites(base_path=self.base_path)
        self.valid_payload = {'form': 'test'}
        self.invalid_payloads = [{'form': ''}]
        self.execute = True
        self.status = False
        self.rtd = True
        self.pre_data = [{'data': {'tag': 'mytag'},
                          'path': reverse('tags-list'),
                          'status': False},
                         {'data': {'workflow': 'myworkflow',
                                   'tag': 'mytag',
                                   'steps': [{'step': 'one', 'role': 'all_two', 'sequence': 0}]},
                          'path': reverse('workflows-list'),
                          'status': True},
                         {'data': {'form': 'test',
                                   'workflow': 'myworkflow',
                                   'tag': 'mytag',
                                   'sections': [{'section': 'sectionOne',
                                                 'role': 'all',
                                                 'sequence': 0,
                                                 'confirmation': 'logging'},
                                                {'section': 'sectionTwo',
                                                 'role': 'all',
                                                 'sequence': 1,
                                                 'predecessors': ['sectionOne'],
                                                 'confirmation': 'logging'}],
                                   'fields_text': [{'section': 'sectionOne',
                                                    'field': 'textfieldOne',
                                                    'mandatory': True,
                                                    'instruction': 'text123',
                                                    'sequence': 0},
                                                   {'section': 'sectionTwo',
                                                    'field': 'textfieldTwo',
                                                    'mandatory': True,
                                                    'instruction': 'text2',
                                                    'sequence': 1}],
                                   'fields_bool': [{'section': 'sectionOne',
                                                    'field': 'boolfieldOne',
                                                    'mandatory': False,
                                                    'instruction': 'text',
                                                    'sequence': 1}]},
                          'path': reverse('forms-list'),
                          'status': True}]


###########################
# /rtd/execution/{number} #
###########################

# get
class GetOneExecution(GetOne):
    def __init__(self, *args, **kwargs):
        super(GetOneExecution, self).__init__(*args, **kwargs)
        self.base_path = BASE_PATH
        self.model = Execution
        self.prerequisites = Prerequisites(base_path=self.base_path)
        self.serializer = ExecutionReadWriteSerializer
        self.execute = True
        self.status = False
        self.rtd = True
        self.ok_object_data = {'form': 'test'}
        self.pre_data = [{'data': {'tag': 'mytag'},
                          'path': reverse('tags-list'),
                          'status': False},
                         {'data': {'workflow': 'myworkflow',
                                   'tag': 'mytag',
                                   'steps': [{'step': 'one', 'role': 'all_two', 'sequence': 0}]},
                          'path': reverse('workflows-list'),
                          'status': True},
                         {'data': {'form': 'test',
                                   'workflow': 'myworkflow',
                                   'sections': [{'section': 'sectionOne',
                                                 'role': 'all',
                                                 'sequence': 0,
                                                 'confirmation': 'logging'},
                                                {'section': 'sectionTwo',
                                                 'role': 'all',
                                                 'sequence': 1,
                                                 'predecessors': ['sectionOne'],
                                                 'confirmation': 'logging'}],
                                   'fields_text': [{'section': 'sectionOne',
                                                    'field': 'textfieldOne',
                                                    'mandatory': True,
                                                    'instruction': 'text123',
                                                    'sequence': 0},
                                                   {'section': 'sectionTwo',
                                                    'field': 'textfieldTwo',
                                                    'mandatory': True,
                                                    'instruction': 'text2',
                                                    'sequence': 1}],
                                   'fields_bool': [{'section': 'sectionOne',
                                                    'field': 'boolfieldOne',
                                                    'mandatory': False,
                                                    'instruction': 'text',
                                                    'sequence': 1}]},
                          'path': reverse('forms-list'),
                          'status': True}]


# delete
class DeleteOneExecution(DeleteOne):
    def __init__(self, *args, **kwargs):
        super(DeleteOneExecution, self).__init__(*args, **kwargs)
        self.base_path = BASE_PATH
        self.model = Execution
        self.prerequisites = Prerequisites(base_path=self.base_path)
        self.serializer = ExecutionReadWriteSerializer
        self.execute = True
        self.rtd = True
        self.ok_object_data = {'form': 'test'}
        self.pre_data = [{'data': {'tag': 'mytag'},
                          'path': reverse('tags-list'),
                          'status': False},
                         {'data': {'workflow': 'myworkflow',
                                   'tag': 'mytag',
                                   'steps': [{'step': 'one', 'role': 'all_two', 'sequence': 0}]},
                          'path': reverse('workflows-list'),
                          'status': True},
                         {'data': {'form': 'test',
                                   'workflow': 'myworkflow',
                                   'sections': [{'section': 'sectionOne',
                                                 'role': 'all',
                                                 'sequence': 0,
                                                 'confirmation': 'logging'},
                                                {'section': 'sectionTwo',
                                                 'role': 'all',
                                                 'sequence': 1,
                                                 'predecessors': ['sectionOne'],
                                                 'confirmation': 'logging'}],
                                   'fields_text': [{'section': 'sectionOne',
                                                    'field': 'textfieldOne',
                                                    'mandatory': True,
                                                    'instruction': 'text123',
                                                    'sequence': 0},
                                                   {'section': 'sectionTwo',
                                                    'field': 'textfieldTwo',
                                                    'mandatory': True,
                                                    'instruction': 'text2',
                                                    'sequence': 1}],
                                   'fields_bool': [{'section': 'sectionOne',
                                                    'field': 'boolfieldOne',
                                                    'mandatory': False,
                                                    'instruction': 'text',
                                                    'sequence': 1}]},
                          'path': reverse('forms-list'),
                          'status': True}]


####################################
# /rtd/execution/{number}/{status} #
####################################

# patch
class PatchOneStatusExecution(PatchOneStatus):
    def __init__(self, *args, **kwargs):
        super(PatchOneStatusExecution, self).__init__(*args, **kwargs)
        self.base_path = BASE_PATH
        self.model = Execution
        self.prerequisites = Prerequisites(base_path=self.base_path)
        self.serializer = ExecutionReadWriteSerializer
        self.execute = True
        self.rtd = True
        self.ok_object_data = {'form': 'test'}
        self.pre_data = [{'data': {'tag': 'mytag'},
                          'path': reverse('tags-list'),
                          'status': False},
                         {'data': {'workflow': 'myworkflow',
                                   'tag': 'mytag',
                                   'steps': [{'step': 'one', 'role': 'all_two', 'sequence': 0}]},
                          'path': reverse('workflows-list'),
                          'status': True},
                         {'data': {'form': 'test',
                                   'workflow': 'myworkflow',
                                   'sections': [{'section': 'sectionOne',
                                                 'role': 'all',
                                                 'sequence': 0,
                                                 'confirmation': 'logging'},
                                                {'section': 'sectionTwo',
                                                 'role': 'all',
                                                 'sequence': 1,
                                                 'predecessors': ['sectionOne'],
                                                 'confirmation': 'logging'}],
                                   'fields_text': [{'section': 'sectionOne',
                                                    'field': 'textfieldOne',
                                                    'mandatory': True,
                                                    'instruction': 'text123',
                                                    'sequence': 0},
                                                   {'section': 'sectionTwo',
                                                    'field': 'textfieldTwo',
                                                    'mandatory': True,
                                                    'instruction': 'text2',
                                                    'sequence': 1}],
                                   'fields_bool': [{'section': 'sectionOne',
                                                    'field': 'boolfieldOne',
                                                    'mandatory': False,
                                                    'instruction': 'text',
                                                    'sequence': 1}]},
                          'path': reverse('forms-list'),
                          'status': True}]
