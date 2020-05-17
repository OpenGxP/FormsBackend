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
from urp.serializers import StatusReadWriteSerializer
from basics.models import AVAILABLE_STATUS, Status

# django imports
from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = 'Initialize required status.'

    def handle(self, *args, **options):
        for item in AVAILABLE_STATUS:
            data = {'status': item}
            serializer = StatusReadWriteSerializer(data=data, context={'method': 'POST', 'function': 'init'})
            if serializer.is_valid():
                # FO-276: added unique check to avoid error on container restart
                _filter = {Status.UNIQUE: data['status']}
                if Status.objects.filter(**_filter).exists():
                    pass
                else:
                    serializer.save()
                    self.stdout.write(self.style.SUCCESS('Added status "{}".'.format(item)))
            else:
                for error in serializer.errors:
                    if serializer.errors[error][0].code != 'unique':
                        self.stderr.write(self.style.ERROR('Data: "{}", error: "{}".'
                                                           .format(data, serializer.errors[error][0])))
