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
from django.core.management.base import BaseCommand
from django.db import connection


class Command(BaseCommand):
    help = 'Create / update views in db.'

    def handle(self, *args, **options):
        cursor = connection.cursor()
        cursor.execute('DROP VIEW IF EXISTS main.urp_executionactualvalueslog;')
        cursor.execute('''
                      CREATE VIEW main.urp_executionactualvalueslog as
                      SELECT
                      bool.id as id,
                      bool.number as number,
                      bool.section as section,
                      bool.field as field,
                      bool.value as value,
                      bool.instruction as instruction,
                      bool.mandatory as mandatory,
                      bool.data_type as data_type,
                      bool.tag as tag,
                      bool.checksum as checksum,
                      bool.user as "user",
                      bool.timestamp as timestamp,
                      bool.action as action,
                      bool.comment as comment,
                      bool.way as way
                      FROM urp_executionboolfieldslog bool
                      UNION
                      SELECT
                      text.id as id,
                      text.number as number,
                      text.section as section,
                      text.field as field,
                      text.value as value,
                      text.instruction as instruction,
                      text.mandatory as mandatory,
                      text.data_type as data_type,
                      text.tag as tag,
                      text.checksum as checksum,
                      text.user as "user",
                      text.timestamp as timestamp,
                      text.action as action,
                      text.comment as comment,
                      text.way as way
                      FROM urp_executiontextfieldslog text;''')

        self.stdout.write(self.style.SUCCESS('Created db views.'))
