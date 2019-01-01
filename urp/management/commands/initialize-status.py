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

# django imports
from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = 'Initialize required status.'

    def handle(self, *args, **options):
        status = ['draft', 'circulation', 'productive', 'blocked', 'inactive', 'archived']
        for item in status:
            data = {'status': item}
            serializer = StatusReadWriteSerializer(data=data, context={'method': 'POST', 'function': 'new'})
            if serializer.is_valid():
                serializer.save()
                self.stdout.write(self.style.SUCCESS('Successfully added status "{}".'.format(item)))
            else:
                for error in serializer.errors:
                    self.stderr.write('Error: {}'.format(serializer.errors[error][0]))
