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
from urp.serializers.settings import SettingsInitialWriteSerializer

# django imports
from django.apps import apps
from django.conf import settings
from django.core.management.base import BaseCommand


def add_setting(self, data):
    serializer = SettingsInitialWriteSerializer(data=data, context={'method': 'POST', 'function': 'init'})
    if serializer.is_valid():
        serializer.save()
        self.stdout.write(self.style.SUCCESS('Successfully added setting key: "{}", value: "{}".'
                                             .format(data['key'], data['value'])))
    else:
        for error in serializer.errors:
            self.stderr.write('Error: {}'.format(serializer.errors[error][0]))


class Command(BaseCommand):
    help = 'Initialize required settings.'

    def handle(self, *args, **options):
        # add initial settings from forms settings
        for key, value in settings.INITIALIZE_SETTINGS.items():
            data = {'key': key,
                    'default': value,
                    'value': value}
            add_setting(self, data)

        # add settings for signature and comment definition
        models = apps.all_models['urp']
        models.update(apps.all_models['basics'])
        for model in models:
            if model == 'tokens' or model == 'status' or model == 'permissions' \
                    or model == 'permissionslog' or model == 'statuslog' or model == 'workflowssteps' \
                    or model == 'profile' or model == 'profilelog' or model == 'inbox':
                continue
            for key, value in models[model].perms.items():
                if key == '01':
                    continue

                # rename vault to passwords
                if model == 'vault':
                    model = 'passwords'

                # add signature setting
                data = {'key': 'dialog.{}.signature.{}'.format(model, value),
                        'default': settings.DEFAULT_DIALOG_SIGNATURE,
                        'value': settings.DEFAULT_DIALOG_SIGNATURE}
                add_setting(self, data)

                # add comment setting
                data = {'key': 'dialog.{}.comment.{}'.format(model, value),
                        'default': settings.DEFAULT_DIALOG_COMMENT,
                        'value': settings.DEFAULT_DIALOG_COMMENT}
                add_setting(self, data)
