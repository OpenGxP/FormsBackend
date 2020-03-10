"""
opengxp.org
Copyright (C) 2018  Henrik Baran

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


# python imports
import sys

# app imports
from urp.serializers.roles import RolesReadWriteSerializer, RolesNewVersionStatusSerializer
from urp.models import Roles

# django imports
from django.core import exceptions
from django.utils import timezone
from django.conf import settings
from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = 'Create role.'

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.model = Roles
        self.role_field = self.model._meta.get_field('role')
        self.permissions_field = self.model._meta.get_field('permissions')

    def add_arguments(self, parser):
        super(Command, self).add_arguments(parser)
        parser.add_argument('--name', dest='name', help='Define a role name.', default=None)
        parser.add_argument('--permissions', dest='perm', help='Comma separated list of permissions. '
                                                               'None = all permissions.', default=None)
        parser.add_argument('--valid_from', dest='valid_from', help='Set a valid from date in '
                                                                    'format "%d-%m-%Y %H:%M:%S".', default=None)

    def handle(self, *args, **options):
        role = options['name']
        if not role:
            self.stderr.write("Error: Role name --name is mandatory.")
            sys.exit(1)
        permissions = options['perm']
        role = self.clean_input(self.role_field, role)
        if not role:
            sys.exit(1)
        if not permissions:
            # get all perms in a comma separated list
            permissions = settings.ALL_PERMISSIONS
        else:
            permissions = self.clean_input(self.permissions_field, permissions)

        valid_from = options['valid_from']
        if not valid_from:
            valid_from = timezone.now()
        else:
            try:
                valid_from = timezone.datetime.strptime(valid_from, '%d-%m-%Y %H:%M:%S')
            except ValueError:
                self.stderr.write('Error: Cannot convert valid from date, please use format "%d-%m-%Y %H:%M:%S".')
                sys.exit(1)
        version = 1
        data = {
            'version': version,
            'role': role,
            'permissions': permissions,
            'valid_from': valid_from
        }
        serializer = RolesReadWriteSerializer(data=data, context={'method': 'POST', 'function': 'init',
                                              'user': settings.DEFAULT_SYSTEM_USER})
        if serializer.is_valid():
            # FO-131: add check if a role with any record already exists
            _filter = {Roles.UNIQUE: role}
            if Roles.objects.filter(**_filter).exists():
                pass
            else:
                serializer.save()
                self.stdout.write(self.style.SUCCESS('Role "{}" created in status "draft".'.format(role)))

                # change status to in circulation
                role = Roles.objects.get(lifecycle_id=serializer.data['lifecycle_id'], version=version)
                serializer_circulation = RolesNewVersionStatusSerializer(role, data={},
                                                                         context={'method': 'PATCH',
                                                                                  'function': 'status_change',
                                                                                  'status': 'circulation',
                                                                                  'user': settings.DEFAULT_SYSTEM_USER,
                                                                                  'disable-sod': True})
                if serializer_circulation.is_valid():
                    serializer_circulation.save()
                    self.stdout.write(self.style.SUCCESS('Role "{}" changed to status "circulation".'
                                                         .format(role.role)))

                    # change status to in productive
                    serializer_productive = RolesNewVersionStatusSerializer(
                        role, data={}, context={'method': 'PATCH', 'function': 'status_change', 'status': 'productive',
                                                'user': settings.DEFAULT_SYSTEM_USER, 'disable-sod': True})
                    if serializer_productive.is_valid():
                        serializer_productive.save()
                        self.stdout.write(self.style.SUCCESS('Role "{}" changed to status "productive".'
                                                             .format(role.role)))
                    else:
                        for error in serializer_productive.errors:
                            self.stderr.write(self.style.ERROR('Data: "{}", error: "{}".'
                                                               .format(data, serializer.errors[error][0])))
                else:
                    for error in serializer_circulation.errors:
                        self.stderr.write(self.style.ERROR('Data: "{}", error: "{}".'
                                                           .format(data, serializer.errors[error][0])))
        else:
            for error in serializer.errors:
                self.stderr.write(self.style.ERROR('Data: "{}", error: "{}".'
                                                   .format(data, serializer.errors[error][0])))

    def clean_input(self, field, value):
        """
        Clean input for model field.
        """
        try:
            val = field.clean(value, None)
        except exceptions.ValidationError as e:
            self.stderr.write("Error: %s" % '; '.join(e.messages))
            val = None
        return val
