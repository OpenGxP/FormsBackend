"""
opengxp.org
Copyright (C) 2019  Henrik Baran

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
from django.conf import settings

# app imports
from urp.decorators import auth_required

# rest imports
from rest_framework.response import Response
from rest_framework.decorators import api_view
from rest_framework.reverse import reverse


@api_view(['GET'])
@auth_required(initial_password_check=False)
def private_root_view(request):
    root = {'base': {'csrftoken': {'url': {'abs': reverse('get_csrf_token', request=request),
                                           'rel': '{}csrftoken'.format(settings.BASE_URL)}},
                     'logout': {'url': {'abs': reverse('logout-view', request=request),
                                        'rel': '{}logout'.format(settings.BASE_URL)}},
                     'meta': {'url': {'abs': '',
                                      'rel': '{}meta/<str:subject>'.format(settings.BASE_URL)}},
            'logout_auto': {'url': {'abs': reverse('logout-auto-view', request=request),
                                    'rel': '{}logout_auto'.format(settings.BASE_URL)}}},
            'user': {'profile': {'url': {'abs': reverse('user-profile-list', request=request),
                                         'rel': '{}user/profile'.format(settings.BASE_URL)}},
                     'change_password': {'url': {'abs': reverse('user-change-password-view', request=request),
                                                 'rel': '{}user/change_password'.format(settings.BASE_URL)}},
                     'change_questions': {'url': {'abs': reverse('user-change-questions-view', request=request),
                                                  'rel': '{}user/change_questions'.format(settings.BASE_URL)}}},
            'navigation': {'admin_ngxp': {'title': 'Non-GxP Administration',
                                          'subjects': {'ldap': {'title': 'LDAP',
                                                                'url': {'abs': reverse('ldap-list', request=request),
                                                                        'rel': '{}admin/ldap'.format(
                                                                            settings.BASE_URL)},
                                                                'log': {'abs': reverse('ldap-log-list',
                                                                                       request=request),
                                                                        'rel': '{}logs/ldap'.format(settings.BASE_URL)},
                                                                'post': True,
                                                                'patch': True,
                                                                'delete': True,
                                                                'version': False},
                                                       'email': {'title': 'Email',
                                                                 'url': {'abs': reverse('email-list', request=request),
                                                                         'rel': '{}admin/email'.format(
                                                                             settings.BASE_URL)},
                                                                 'log': {'abs': reverse('email-log-list',
                                                                                        request=request),
                                                                         'rel': '{}logs/email'.format(
                                                                             settings.BASE_URL)},
                                                                 'post': True,
                                                                 'patch': True,
                                                                 'delete': True,
                                                                 'version': False},
                                                       'settings': {'title': 'Settings',
                                                                    'url': {'abs': reverse('settings-list',
                                                                                           request=request),
                                                                            'rel': '{}admin/settings'.format(
                                                                            settings.BASE_URL)},
                                                                    'log': {'abs': reverse('settings-log-list',
                                                                                           request=request),
                                                                            'rel': '{}logs/settings'.format(
                                                                                settings.BASE_URL)},
                                                                    'post': False,
                                                                    'patch': True,
                                                                    'delete': False,
                                                                    'version': False},
                                                       'passwords': {'title': 'Passwords',
                                                                     'url': {'abs': reverse('users-password-list',
                                                                                            request=request),
                                                                             'rel': '{}admin/passwords'.format(
                                                                                 settings.BASE_URL)},
                                                                     'log': {'abs': reverse('users-log-list',
                                                                                            request=request),
                                                                             'rel': '{}logs/users'.format(
                                                                                 settings.BASE_URL)},
                                                                     'post': False,
                                                                     'patch': True,
                                                                     'delete': False,
                                                                     'version': False},
                                                       'tags': {'title': 'Tags',
                                                                'url': {'abs': reverse('tags-list', request=request),
                                                                        'rel': '{}admin/tags'.format(
                                                                            settings.BASE_URL)},
                                                                'log': {'abs': reverse('tags-log-list',
                                                                                       request=request),
                                                                        'rel': '{}logs/tags'.format(
                                                                            settings.BASE_URL)},
                                                                'post': True,
                                                                'patch': True,
                                                                'delete': True,
                                                                'version': False},
                                                       'spaces': {'title': 'Spaces',
                                                                  'url': {'abs': reverse('spaces-list',
                                                                                         request=request),
                                                                          'rel': '{}admin/spaces'.format(
                                                                              settings.BASE_URL)},
                                                                  'log': {'abs': reverse('spaces-log-list',
                                                                                         request=request),
                                                                          'rel': '{}logs/spaces'.format(
                                                                              settings.BASE_URL)},
                                                                  'post': True,
                                                                  'patch': True,
                                                                  'delete': True,
                                                                  'version': False}}},
                           'admin_gxp': {'title': 'GxP Administration',
                                         'subjects': {'roles': {'title': 'Roles',
                                                                'url': {'abs': reverse('roles-list', request=request),
                                                                        'rel': '{}admin/roles'.format(
                                                                            settings.BASE_URL)},
                                                                'log': {'abs': reverse('roles-log-list',
                                                                                       request=request),
                                                                        'rel': '{}logs/roles'.format(
                                                                            settings.BASE_URL)},
                                                                'post': True,
                                                                'patch': True,
                                                                'delete': True,
                                                                'version': True},
                                                      'users': {'title': 'Users',
                                                                'url': {'abs': reverse('users-list', request=request),
                                                                        'rel': '{}admin/users'.format(
                                                                            settings.BASE_URL)},
                                                                'log': {'abs': reverse('users-log-list',
                                                                                       request=request),
                                                                        'rel': '{}logs/users'.format(
                                                                            settings.BASE_URL)},
                                                                'post': True,
                                                                'patch': True,
                                                                'delete': True,
                                                                'version': True},
                                                      'sod': {'title': 'SoD',
                                                              'url': {'abs': reverse('sod-list', request=request),
                                                                      'rel': '{}admin/sod'.format(settings.BASE_URL)},
                                                              'log': {'abs': reverse('sod-log-list', request=request),
                                                                      'rel': '{}logs/sod'.format(settings.BASE_URL)},
                                                              'post': True,
                                                              'patch': True,
                                                              'delete': True,
                                                              'version': True}}},
                           'md_gxp': {'title': 'GxP Master Data',
                                      'subjects': {'lists': {'title': 'Lists',
                                                             'url': {'abs': reverse('lists-list', request=request),
                                                                     'rel': '{}md/lists'.format(settings.BASE_URL)},
                                                             'log': {'abs': reverse('lists-log-list', request=request),
                                                                     'rel': '{}logs/lists'.format(settings.BASE_URL)},
                                                             'post': True,
                                                             'patch': True,
                                                             'delete': True,
                                                             'version': True},
                                                   'workflows': {'title': 'Workflows',
                                                                 'url': {'abs': reverse('workflows-list',
                                                                                        request=request),
                                                                         'rel': '{}md/workflows'.format(
                                                                             settings.BASE_URL)},
                                                                 'log': {'abs': reverse('workflows-log-list',
                                                                                        request=request),
                                                                         'rel': '{}logs/workflows'.format(
                                                                             settings.BASE_URL)},
                                                                 'post': True,
                                                                 'patch': True,
                                                                 'delete': True,
                                                                 'version': True}}},
                           'logs': {'title': 'Logs',
                                    'subjects': {'central': {'title': 'Central',
                                                             'url': {'abs': reverse('central-log-list',
                                                                                    request=request),
                                                                     'rel': '{}logs/central'.format(
                                                                         settings.BASE_URL)}},
                                                 'access': {'title': 'Access',
                                                            'url': {'abs': reverse('access-log-list', request=request),
                                                                    'rel': '{}logs/access'.format(settings.BASE_URL)}},
                                                 'roles': {'title': 'Roles',
                                                           'url': {'abs': reverse('roles-log-list', request=request),
                                                                   'rel': '{}logs/roles'.format(settings.BASE_URL)}},
                                                 'ldap': {'title': 'LDAP',
                                                          'url': {'abs': reverse('ldap-log-list', request=request),
                                                                  'rel': '{}logs/ldap'.format(settings.BASE_URL)}},
                                                 'email': {'title': 'Email',
                                                           'url': {'abs': reverse('email-log-list', request=request),
                                                                   'rel': '{}logs/email'.format(settings.BASE_URL)}},
                                                 'users': {'title': 'Users',
                                                           'url': {'abs': reverse('users-log-list', request=request),
                                                                   'rel': '{}logs/users'.format(settings.BASE_URL)}},
                                                 'tags': {'title': 'Tags',
                                                          'url': {'abs': reverse('tags-log-list', request=request),
                                                                  'rel': '{}logs/tags'.format(settings.BASE_URL)}},
                                                 'spaces': {'title': 'Spaces',
                                                            'url': {'abs': reverse('spaces-log-list', request=request),
                                                                    'rel': '{}logs/spaces'.format(settings.BASE_URL)}},
                                                 'sod': {'title': 'SoD',
                                                         'url': {'abs': reverse('sod-log-list', request=request),
                                                                 'rel': '{}logs/sod'.format(settings.BASE_URL)}},
                                                 'settings': {'title': 'Settings',
                                                              'url': {'abs': reverse('settings-log-list',
                                                                                     request=request),
                                                                      'rel': '{}logs/settings'.format(
                                                                                settings.BASE_URL)}},
                                                 'lists': {'title': 'Lists',
                                                           'url': {'abs': reverse('lists-log-list', request=request),
                                                                   'rel': '{}logs/lists'.format(settings.BASE_URL)}}}}}}

    return Response(root)
