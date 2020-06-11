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
from urp.models.settings import Settings
from urp.models.execution.execution import Execution

# django imports
from django.apps import apps
from django.conf import settings
from django.core.management.base import BaseCommand


def add_setting(self, data):
    serializer = SettingsInitialWriteSerializer(data=data, context={'method': 'POST', 'function': 'init'})
    if serializer.is_valid():
        # FO-276: added unique check to avoid error on container restart
        _filter = {Settings.UNIQUE: data['key']}
        if Settings.objects.filter(**_filter).exists():
            pass
        else:
            serializer.save()
            self.stdout.write(self.style.SUCCESS('Added setting key: "{}", value: "{}".'
                                                 .format(data['key'], data['value'])))
    else:
        for error in serializer.errors:
            if serializer.errors[error][0].code != 'unique':
                self.stderr.write(self.style.ERROR('Data: "{}", error: "{}".'
                                                   .format(data, serializer.errors[error][0])))


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
            if not models[model].objects.COM_SIG_SETTINGS or models[model].objects.IS_LOG:
                continue
            # ... manually add setting for form section comment
            if model == Execution.MODEL_CONTEXT.lower():
                data = {'key': 'dialog.{}.comment.{}'.format(model, settings.SECTION_PERM),
                        'default': settings.DEFAULT_DIALOG_COMMENT_SECTION,
                        'value': settings.DEFAULT_DIALOG_COMMENT_SECTION}
                add_setting(self, data)
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
