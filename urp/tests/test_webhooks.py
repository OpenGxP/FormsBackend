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
from urp.models.webhooks import WebHooks
from urp.serializers.webhooks import WebHooksReadWriteSerializer

# test imports
from urp.tests import Prerequisites, GetAll, PostNew, GetOne, PostNewVersion, DeleteOne, PatchOne, PatchOneStatus


BASE_PATH = reverse('webhooks-list')


####################
# /admin/webhooks/ #
####################

# get
class GetAllWebHooks(GetAll):
    def __init__(self, *args, **kwargs):
        super(GetAllWebHooks, self).__init__(*args, **kwargs)
        self.base_path = BASE_PATH
        self.model = WebHooks
        self.serializer = WebHooksReadWriteSerializer
        self.execute = True


# post
class PostNewWebHooks(PostNew):
    def __init__(self, *args, **kwargs):
        super(PostNewWebHooks, self).__init__(*args, **kwargs)
        self.base_path = BASE_PATH
        self.model = WebHooks
        self.prerequisites = Prerequisites(base_path=self.base_path)
        self.valid_payload = {'webhook': 'test',
                              'url': 'http://www.google.com',
                              'form': 'test'}
        self.invalid_payloads = [dict(),
                                 {'webhook': ''},
                                 {'webhook': 'test',
                                  'url': 'abcd',
                                  'form': 'test'},
                                 {'webhook': 'test',
                                  'url': 'http://www.google.com',
                                  'form': 'abcd'}]
        self.execute = True
        self.pre_data = [{'data': {'workflow': 'myworkflow',
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
                                                    'sequence': 1}]},
                          'path': reverse('forms-list'),
                          'status': True}]


#############################################
# /admin/webhooks/{lifecycle_id}/{version}/ #
#############################################

# get
class GetOneWebHook(GetOne):
    def __init__(self, *args, **kwargs):
        super(GetOneWebHook, self).__init__(*args, **kwargs)
        self.base_path = BASE_PATH
        self.model = WebHooks
        self.prerequisites = Prerequisites(base_path=self.base_path)
        self.serializer = WebHooksReadWriteSerializer
        self.ok_object_data = {'webhook': 'test',
                               'url': 'http://www.google.com',
                               'form': 'test'}
        self.execute = True
        self.pre_data = [{'data': {'workflow': 'myworkflow',
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
                                                    'sequence': 1}]},
                          'path': reverse('forms-list'),
                          'status': True}]


# post
class PostNewVersionWebhook(PostNewVersion):
    def __init__(self, *args, **kwargs):
        super(PostNewVersionWebhook, self).__init__(*args, **kwargs)
        self.base_path = BASE_PATH
        self.model = WebHooks
        self.prerequisites = Prerequisites(base_path=self.base_path)
        self.serializer = WebHooksReadWriteSerializer
        self.ok_object_data = {'webhook': 'test',
                               'url': 'http://www.google.com',
                               'form': 'test'}
        self.fail_object_draft_data = {'webhook': 'test_draft',
                                       'url': 'http://www.google.com',
                                       'form': 'test'}
        self.fail_object_circulation_data = {'webhook': 'test_circ',
                                             'url': 'http://www.google.com',
                                             'form': 'test'}
        self.execute = True
        self.pre_data = [{'data': {'workflow': 'myworkflow',
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
                                                    'sequence': 1}]},
                          'path': reverse('forms-list'),
                          'status': True}]


# delete
class DeleteOneWebHook(DeleteOne):
    def __init__(self, *args, **kwargs):
        super(DeleteOneWebHook, self).__init__(*args, **kwargs)
        self.base_path = BASE_PATH
        self.model = WebHooks
        self.prerequisites = Prerequisites(base_path=self.base_path)
        self.serializer = WebHooksReadWriteSerializer
        self.ok_object_data = {'webhook': 'test',
                               'url': 'http://www.google.com',
                               'form': 'test'}
        self.execute = True
        self.pre_data = [{'data': {'workflow': 'myworkflow',
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
                                                    'sequence': 1}]},
                          'path': reverse('forms-list'),
                          'status': True}]


# patch
class PatchOneWebHook(PatchOne):
    def __init__(self, *args, **kwargs):
        super(PatchOneWebHook, self).__init__(*args, **kwargs)
        self.base_path = BASE_PATH
        self.model = WebHooks
        self.prerequisites = Prerequisites(base_path=self.base_path)
        self.serializer = WebHooksReadWriteSerializer
        self.ok_object_data = {'webhook': 'test',
                               'url': 'http://www.google.com',
                               'form': 'test'}
        self.valid_payload = {'webhook': 'test',
                              'url': 'http://www.google.de',
                              'form': 'test'}
        self.invalid_payload = {'webhook': 'test',
                                'url': 'asdf',
                                'form': 'test'}
        self.unique_invalid_payload = {'webhook': 'testneu',
                                       'url': 'http://www.google.com',
                                       'form': 'test'}
        self.execute = True
        self.pre_data = [{'data': {'workflow': 'myworkflow',
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
                                                    'sequence': 1}]},
                          'path': reverse('forms-list'),
                          'status': True}]


#####################################################
# /admin/webhooks/{lifecycle_id}/{version}/{status} #
#####################################################

# patch
class PatchOneStatusWebHook(PatchOneStatus):
    def __init__(self, *args, **kwargs):
        super(PatchOneStatusWebHook, self).__init__(*args, **kwargs)
        self.base_path = BASE_PATH
        self.model = WebHooks
        self.prerequisites = Prerequisites(base_path=self.base_path)
        self.serializer = WebHooksReadWriteSerializer
        self.ok_object_data = {'webhook': 'test',
                               'url': 'http://www.google.com',
                               'form': 'test'}
        self.execute = True
        self.pre_data = [{'data': {'workflow': 'myworkflow',
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
                                                    'sequence': 1}]},
                          'path': reverse('forms-list'),
                          'status': True}]
