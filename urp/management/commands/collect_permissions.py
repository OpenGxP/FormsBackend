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


# app imports
from urp.serializers import PermissionsReadWriteSerializer

# django imports
from django.core.management.base import BaseCommand, CommandError
from django.apps import apps


class Command(BaseCommand):
    help = 'Collect permissions from models.'

    def handle(self, *args, **options):
        models = apps.all_models['urp']
        models.update(apps.all_models['basics'])
        for model in models:
            for perm in models[model].perms:
                data = {'model': model,
                        'permission': perm,
                        'key': '{}.{}'.format(model[:2], perm[:3])}
                serializer = PermissionsReadWriteSerializer(data=data, context={'method': 'POST', 'function': 'new'})
                if serializer.is_valid():
                    serializer.save()
                else:
                    raise CommandError('Data is not valid ({}). Error: {}.'.format(data, serializer.errors))
        self.stdout.write(self.style.SUCCESS('Successfully collected all permissions.'))
