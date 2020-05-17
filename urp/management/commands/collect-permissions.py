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
from urp.models import Permissions

# django imports
from django.core.management.base import BaseCommand
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
            # FO-276: added unique check to avoid error on container restart
            _filter = {Permissions.UNIQUE: data['key']}
            if Permissions.objects.filter(**_filter).exists():
                pass
            else:
                serializer.save()
                self.stdout.write(self.style.SUCCESS('Added permission "global.all".'))
        else:
            for error in serializer.errors:
                if serializer.errors[error][0].code != 'unique':
                    self.stderr.write(self.style.ERROR('Data: "{}", error: "{}".'
                                                       .format(data, serializer.errors[error][0])))
        models = apps.all_models['urp']
        models.update(apps.all_models['basics'])
        for model in models:
            if models[model].objects.NO_PERMISSIONS:
                continue
            for key, value in models[model].perms.items():
                _model = model
                if model == 'vault':
                    _model = 'passwords'
                data = {'model': _model,
                        'permission': value,
                        'key': '{}.{}'.format(models[model].MODEL_ID, key)}
                serializer = PermissionsReadWriteSerializer(data=data, context={'method': 'POST', 'function': 'init'})
                if serializer.is_valid():
                    # FO-276: added unique check to avoid error on container restart
                    _filter = {Permissions.UNIQUE: data['key']}
                    if Permissions.objects.filter(**_filter).exists():
                        pass
                    else:
                        serializer.save()
                        self.stdout.write(self.style.SUCCESS('Added permission "{}.{}".'.format(data['model'],
                                                                                                data['permission'])))
                else:
                    for error in serializer.errors:
                        if serializer.errors[error][0].code != 'unique':
                            self.stderr.write(self.style.ERROR('Data: "{}", error: "{}".'
                                                               .format(data, serializer.errors[error][0])))
