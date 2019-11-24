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


# app imports
from urp.serializers import PermissionsReadWriteSerializer

# django imports
from django.core.management.base import BaseCommand, CommandError
from django.apps import apps
from django.conf import settings


class Command(BaseCommand):
    help = 'Collect permissions from models.'

    def handle(self, *args, **options):
        # add all permission
        data = {'model': 'global',
                'permission': 'all',
                'key': '{}'.format(settings.ALL_PERMISSIONS)}
        serializer = PermissionsReadWriteSerializer(data=data, context={'method': 'POST', 'function': 'init'})
        if serializer.is_valid():
            serializer.save()
        else:
            raise CommandError('Data is not valid ({}). Error: {}.'.format(data, serializer.errors))
        models = apps.all_models['urp']
        models.update(apps.all_models['basics'])
        for model in models:
            if model == 'tokens' or model == 'vault' or model == 'status' or model == 'permissions' \
                    or model == 'permissionslog' or model == 'statuslog' or model == 'workflowssteps' \
                    or model == 'profile' or model == 'profilelog' or model == 'inbox':
                continue
            for key, value in models[model].perms.items():
                data = {'model': model,
                        'permission': value,
                        'key': '{}.{}'.format(models[model].MODEL_ID, key)}
                serializer = PermissionsReadWriteSerializer(data=data, context={'method': 'POST', 'function': 'init'})
                if serializer.is_valid():
                    serializer.save()
                else:
                    raise CommandError('Data is not valid ({}). Error: {}.'.format(data, serializer.errors))
        self.stdout.write(self.style.SUCCESS('Successfully collected all permissions.'))
