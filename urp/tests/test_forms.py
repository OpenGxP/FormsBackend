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
from urp.models.forms.forms import Forms
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
                              'fields_text': [{'section': 0,
                                               'field': 'textfieldOne',
                                               'mandatory': True,
                                               'instruction': 'text123',
                                               'sequence': 0},
                                              {'section': 1,
                                               'field': 'textfieldTwo',
                                               'mandatory': True,
                                               'instruction': 'text2',
                                               'sequence': 1}],
                              'fields_bool': [{'section': 0,
                                               'field': 'boolfieldOne',
                                               'mandatory': False,
                                               'instruction': 'text',
                                               'sequence': 1}]}
        self.invalid_payloads = [dict(),
                                 {'form': ''},
                                 # FO-318: added test to verify that two text fields in different sections
                                 # return proper error
                                 {'form': 'test',
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
                                  'fields_text': [{'section': 0,
                                                   'field': 'textfieldOne',
                                                   'mandatory': True,
                                                   'instruction': 'text123',
                                                   'sequence': 0},
                                                  {'section': 1,
                                                   'field': 'textfieldOne',
                                                   'mandatory': True,
                                                   'instruction': 'text2',
                                                   'sequence': 1}],
                                  'fields_bool': [{'section': 0,
                                                   'field': 'boolfieldOne',
                                                   'mandatory': False,
                                                   'instruction': 'text',
                                                   'sequence': 1}]}]
        self.execute = True
        self.pre_data = [{'data': {'tag': 'mytag'},
                          'path': reverse('tags-list'),
                          'status': False},
                         {'data': {'workflow': 'myworkflow',
                                   'tag': 'mytag',
                                   'steps': [{'step': 'one', 'role': 'all', 'sequence': 0}]},
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
                               'fields_text': [{'section': 0,
                                                'field': 'textfieldOne',
                                                'mandatory': True,
                                                'instruction': 'text123',
                                                'sequence': 0},
                                               {'section': 1,
                                                'field': 'textfieldTwo',
                                                'mandatory': True,
                                                'instruction': 'text2',
                                                'sequence': 1}],
                               'fields_bool': [{'section': 0,
                                                'field': 'boolfieldOne',
                                                'mandatory': False,
                                                'instruction': 'text',
                                                'sequence': 1}]}
        self.execute = True
        self.pre_data = [{'data': {'tag': 'mytag'},
                          'path': reverse('tags-list'),
                          'status': False},
                         {'data': {'workflow': 'myworkflow',
                                   'tag': 'mytag',
                                   'steps': [{'step': 'one', 'role': 'all', 'sequence': 0}]},
                          'path': reverse('workflows-list'),
                          'status': True},
                         {'data': {'space': 'test',
                                   'users': [self.prerequisites.username],
                                   'tags': ['mytag']},
                          'path': reverse('spaces-list'),
                          'status': False}]


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
                               'fields_text': [{'section': 0,
                                                'field': 'textfieldOne',
                                                'mandatory': True,
                                                'instruction': 'text123',
                                                'sequence': 0},
                                               {'section': 1,
                                                'field': 'textfieldTwo',
                                                'mandatory': True,
                                                'instruction': 'text2',
                                                'sequence': 1}],
                               'fields_bool': [{'section': 0,
                                                'field': 'boolfieldOne',
                                                'mandatory': False,
                                                'instruction': 'text',
                                                'sequence': 1}]}
        self.fail_object_draft_data = {'form': 'testfail',
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
                                       'fields_text': [{'section': 0,
                                                        'field': 'textfieldOne',
                                                        'mandatory': True,
                                                        'instruction': 'text123',
                                                        'sequence': 0},
                                                       {'section': 1,
                                                        'field': 'textfieldTwo',
                                                        'mandatory': True,
                                                        'instruction': 'text2',
                                                        'sequence': 1}],
                                       'fields_bool': [{'section': 0,
                                                        'field': 'boolfieldOne',
                                                        'mandatory': False,
                                                        'instruction': 'text',
                                                        'sequence': 1}]}
        self.fail_object_circulation_data = {'form': 'testcircfail',
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
                                             'fields_text': [{'section': 0,
                                                              'field': 'textfieldOne',
                                                              'mandatory': True,
                                                              'instruction': 'text123',
                                                              'sequence': 0},
                                                             {'section': 1,
                                                              'field': 'textfieldTwo',
                                                              'mandatory': True,
                                                              'instruction': 'text2',
                                                              'sequence': 1}],
                                             'fields_bool': [{'section': 0,
                                                              'field': 'boolfieldOne',
                                                              'mandatory': False,
                                                              'instruction': 'text',
                                                              'sequence': 1}]}
        self.execute = True
        self.pre_data = [{'data': {'tag': 'mytag'},
                          'path': reverse('tags-list'),
                          'status': False},
                         {'data': {'workflow': 'myworkflow',
                                   'tag': 'mytag',
                                   'steps': [{'step': 'one', 'role': 'all_two', 'sequence': 0}]},
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
                               'fields_text': [{'section': 0,
                                                'field': 'textfieldOne',
                                                'mandatory': True,
                                                'instruction': 'text123',
                                                'sequence': 0},
                                               {'section': 1,
                                                'field': 'textfieldTwo',
                                                'mandatory': True,
                                                'instruction': 'text2',
                                                'sequence': 1}],
                               'fields_bool': [{'section': 0,
                                                'field': 'boolfieldOne',
                                                'mandatory': False,
                                                'instruction': 'text',
                                                'sequence': 1}]}
        self.execute = True
        self.pre_data = [{'data': {'tag': 'mytag'},
                          'path': reverse('tags-list'),
                          'status': False},
                         {'data': {'workflow': 'myworkflow',
                                   'tag': 'mytag',
                                   'steps': [{'step': 'one', 'role': 'all_two', 'sequence': 0}]},
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
                               'fields_text': [{'section': 0,
                                                'field': 'textfieldOne',
                                                'mandatory': True,
                                                'instruction': 'text123',
                                                'sequence': 0},
                                               {'section': 1,
                                                'field': 'textfieldTwo',
                                                'mandatory': True,
                                                'instruction': 'text2',
                                                'sequence': 1}],
                               'fields_bool': [{'section': 0,
                                                'field': 'boolfieldOne',
                                                'mandatory': False,
                                                'instruction': 'text',
                                                'sequence': 1}]}
        self.valid_payload = {'form': 'test',
                              'workflow': 'myworkflow',
                              'tag': 'mytag',
                              'sections': [{'section': 'sectionOne',
                                            'role': 'all',
                                            'sequence': 0,
                                            'confirmation': 'signature'},
                                           {'section': 'sectionTwo',
                                            'role': 'all_two',
                                            'sequence': 1,
                                            'predecessors': ['sectionOne'],
                                            'confirmation': 'logging'}],
                              'fields_text': [{'section': 0,
                                               'field': 'textfieldOne',
                                               'mandatory': True,
                                               'instruction': 'noinstruction',
                                               'sequence': 0}],
                              'fields_bool': [{'section': 0,
                                               'field': 'boolfieldOne',
                                               'mandatory': True,
                                               'instruction': 'text',
                                               'sequence': 1}]}
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
                                   'steps': [{'step': 'one', 'role': 'all_two', 'sequence': 0}]},
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
                               'fields_text': [{'section': 0,
                                                'field': 'textfieldOne',
                                                'mandatory': True,
                                                'instruction': 'text123',
                                                'sequence': 0},
                                               {'section': 1,
                                                'field': 'textfieldTwo',
                                                'mandatory': True,
                                                'instruction': 'text2',
                                                'sequence': 1}],
                               'fields_bool': [{'section': 0,
                                                'field': 'boolfieldOne',
                                                'mandatory': False,
                                                'instruction': 'text',
                                                'sequence': 1}]}
        self.execute = True
        self.sub_table = False
        self.pre_data = [{'data': {'tag': 'mytag'},
                          'path': reverse('tags-list'),
                          'status': False},
                         {'data': {'workflow': 'myworkflow',
                                   'tag': 'mytag',
                                   'steps': [{'step': 'one', 'role': 'all_two', 'sequence': 0}]},
                          'path': reverse('workflows-list'),
                          'status': True}]
