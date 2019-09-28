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
from urp.models.workflows import Workflows
from urp.serializers.workflows import WorkflowsReadWriteSerializer

# test imports
from urp.tests import Prerequisites, GetAll, PostNew, GetOne, PostNewVersion, DeleteOne, PatchOne, PatchOneStatus


BASE_PATH = reverse('workflows-list')


##################
# /md/workflows/ #
##################

# get
class GetAllWorkflows(GetAll):
    def __init__(self, *args, **kwargs):
        super(GetAllWorkflows, self).__init__(*args, **kwargs)
        self.base_path = BASE_PATH
        self.model = Workflows
        self.serializer = WorkflowsReadWriteSerializer
        self.execute = True


# post
class PostNewWorkflow(PostNew):
    def __init__(self, *args, **kwargs):
        super(PostNewWorkflow, self).__init__(*args, **kwargs)
        self.base_path = BASE_PATH
        self.model = Workflows
        self.prerequisites = Prerequisites(base_path=self.base_path)
        self.valid_payload = {'workflow': 'test',
                              'tag': 'mytag',
                              'steps': [{'step': 'one', 'role': 'all', 'sequence': 0},
                                        {'step': 'two', 'role': 'all', 'sequence': 1, 'predecessors': ['one']}]}
        self.invalid_payloads = [dict(),
                                 {'workflow': ''},
                                 {'workflow': 'testnew',
                                  'tag': 'ddssd',
                                  'steps': [{'step': 'one', 'role': 'all', 'sequence': 0},
                                            {'step': 'two', 'role': 'all', 'sequence': 1, 'predecessors': ['one']}]},
                                 {'workflow': 'testthree',
                                  'tag': 'mytag',
                                  'steps': [{'step': 'one', 'role': 'all', 'sequence': 0},
                                            {'step': 'one', 'role': 'all', 'sequence': 1, 'predecessors': ['one']}]},
                                 {'workflow': 'testfour',
                                  'tag': 'mytag',
                                  'steps': [{'step': 'one', 'role': 'noexist', 'sequence': 0},
                                            {'step': 'two', 'role': 'all', 'sequence': 1, 'predecessors': ['one']}]},
                                 {'workflow': 'testfive',
                                  'tag': 'mytag',
                                  'steps': [{'step': 'one', 'role': 'all', 'sequence': 0, 'predecessors': ['one']},
                                            {'step': 'two', 'role': 'all', 'sequence': 1}]},
                                 {'workflow': 'testsix',
                                  'tag': 'mytag',
                                  'steps': [{'step': 'one', 'role': 'all', 'sequence': 0},
                                            {'step': 'two', 'role': 'all', 'sequence': 1}]},
                                 {'workflow': 'testseven',
                                  'tag': 'mytag',
                                  'steps': [{'step': 'one', 'role': 'all', 'sequence': 0},
                                            {'step': 'two', 'role': 'all', 'sequence': 0}]},
                                 # FO-191: new test to verify that self reference for steps is not possible
                                 {'workflow': 'test',
                                  'tag': 'mytag',
                                  'steps': [{'step': 'one', 'role': 'all', 'sequence': 0},
                                            {'step': 'two', 'role': 'all', 'sequence': 1, 'predecessors': ['two']}]},
                                 ]
        self.execute = True
        self.sub_table = True
        self.pre_data = [{'data': {'tag': 'mytag'},
                          'path': reverse('tags-list'),
                          'status': False}]


###########################################
# /md/workflows/{lifecycle_id}/{version}/ #
###########################################

# get
class GetOneWorkflow(GetOne):
    def __init__(self, *args, **kwargs):
        super(GetOneWorkflow, self).__init__(*args, **kwargs)
        self.base_path = BASE_PATH
        self.model = Workflows
        self.prerequisites = Prerequisites(base_path=self.base_path)
        self.serializer = WorkflowsReadWriteSerializer
        self.ok_object_data = {'workflow': 'test',
                               'tag': 'mytag',
                               'steps': [{'step': 'one', 'role': 'all', 'sequence': 0},
                                         {'step': 'two', 'role': 'all', 'sequence': 1, 'predecessors': ['one']}]}
        self.execute = True
        self.pre_data = [{'data': {'tag': 'mytag'},
                          'path': reverse('tags-list'),
                          'status': False},
                         {'data': {'space': 'test',
                                   'tags': ['mytag'],
                                   'users': [self.prerequisites.username],
                                   'status': False},
                          'path': reverse('spaces-list'),
                          'status': False}]


# post
class PostNewVersionWorkflow(PostNewVersion):
    def __init__(self, *args, **kwargs):
        super(PostNewVersionWorkflow, self).__init__(*args, **kwargs)
        self.base_path = BASE_PATH
        self.model = Workflows
        self.prerequisites = Prerequisites(base_path=self.base_path)
        self.serializer = WorkflowsReadWriteSerializer
        self.ok_object_data = {'workflow': 'test',
                               'tag': 'mytag',
                               'steps': [{'step': 'one', 'role': 'all', 'sequence': 0},
                                         {'step': 'two', 'role': 'all', 'sequence': 1, 'predecessors': ['one']}]}
        self.fail_object_draft_data = {'workflow': 'test_draft',
                                       'tag': 'mytag',
                                       'steps': [{'step': 'one', 'role': 'all', 'sequence': 0},
                                                 {'step': 'two', 'role': 'all', 'sequence': 1,
                                                  'predecessors': ['one']}]}
        self.fail_object_circulation_data = {'workflow': 'test_circ',
                                             'tag': 'mytag',
                                             'steps': [{'step': 'one', 'role': 'all', 'sequence': 0},
                                                       {'step': 'two', 'role': 'all', 'sequence': 1,
                                                        'predecessors': ['one']}]}
        self.execute = True
        self.sub_table = True
        self.pre_data = [{'data': {'tag': 'mytag'},
                          'path': reverse('tags-list'),
                          'status': False}]


# delete
class DeleteOneWorkflow(DeleteOne):
    def __init__(self, *args, **kwargs):
        super(DeleteOneWorkflow, self).__init__(*args, **kwargs)
        self.base_path = BASE_PATH
        self.model = Workflows
        self.prerequisites = Prerequisites(base_path=self.base_path)
        self.serializer = WorkflowsReadWriteSerializer
        self.ok_object_data = {'workflow': 'test',
                               'tag': 'mytag',
                               'steps': [{'step': 'one', 'role': 'all', 'sequence': 0},
                                         {'step': 'two', 'role': 'all', 'sequence': 1, 'predecessors': ['one']}]}
        self.execute = True
        self.sub_table = True
        self.pre_data = [{'data': {'tag': 'mytag'},
                          'path': reverse('tags-list'),
                          'status': False}]


# patch
class PatchOneWorkflow(PatchOne):
    def __init__(self, *args, **kwargs):
        super(PatchOneWorkflow, self).__init__(*args, **kwargs)
        self.base_path = BASE_PATH
        self.model = Workflows
        self.prerequisites = Prerequisites(base_path=self.base_path)
        self.serializer = WorkflowsReadWriteSerializer
        self.ok_object_data = {'workflow': 'test',
                               'tag': 'mytag',
                               'steps': [{'step': 'one', 'role': 'all', 'sequence': 0},
                                         {'step': 'two', 'role': 'all', 'sequence': 1, 'predecessors': ['one']}]}
        self.valid_payload = {'workflow': 'test',
                              'tag': 'mytag',
                              'steps': [{'step': 'one', 'role': 'all', 'text': 'test', 'sequence': 0},
                                        {'step': 'two', 'role': 'all', 'sequence': 1, 'predecessors': ['one']}]}
        self.invalid_payload = {'workflow': '',
                                'tag': 'mytag',
                                'steps': [{'step': 'one', 'role': 'all', 'sequence': 0},
                                          {'step': 'two', 'role': 'all', 'sequence': 1, 'predecessors': ['one']}]}
        self.unique_invalid_payload = {'workflow': 'testneu',
                                       'tag': 'mytag',
                                       'steps': [{'step': 'one', 'role': 'all', 'sequence': 0},
                                                 {'step': 'two', 'role': 'all', 'sequence': 1,
                                                  'predecessors': ['one']}]}
        self.execute = True
        self.sub_table = True
        self.pre_data = [{'data': {'tag': 'mytag'},
                          'path': reverse('tags-list'),
                          'status': False}]


###################################################
# /md/workflows/{lifecycle_id}/{version}/{status} #
###################################################

# patch
class PatchOneStatusWorkflow(PatchOneStatus):
    def __init__(self, *args, **kwargs):
        super(PatchOneStatusWorkflow, self).__init__(*args, **kwargs)
        self.base_path = BASE_PATH
        self.model = Workflows
        self.prerequisites = Prerequisites(base_path=self.base_path)
        self.serializer = WorkflowsReadWriteSerializer
        self.ok_object_data = {'workflow': 'test',
                               'tag': 'mytag',
                               'steps': [{'step': 'one', 'role': 'all', 'sequence': 0},
                                         {'step': 'two', 'role': 'all', 'sequence': 1, 'predecessors': ['one']}]}
        self.execute = True
        self.sub_table = True
        self.pre_data = [{'data': {'tag': 'mytag'},
                          'path': reverse('tags-list'),
                          'status': False}]
