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
import os
import json
import uuid as python_uuid

# projects imports
from forms.settings import BASE_DIR, require_file

# app imports
from basics.custom import generate_checksum, generate_to_hash

# django imports
from django.utils import timezone


# fixtures dir
FIXTURES_DIR_URP = os.path.join(BASE_DIR, 'urp/fixtures/')
FIXTURES_DIR_BASIC = os.path.join(BASE_DIR, 'basics/fixtures/')


class Fixtures(object):
    def __init__(self):
        self._permissions = ''
        self._fixture = None
        self._status = {}

    @property
    def fixture(self):
        return self._fixture

    @fixture.setter
    def fixture(self, value):
        self._fixture = value

    @property
    def permissions(self):
        return self._permissions

    @permissions.setter
    def permissions(self, value):
        self._permissions += '{},'.format(value)

    @property
    def status(self):
        return self._status

    @status.setter
    def status(self, value):
        self._status = value

    def load_fixture(self, path, fixture):
        self.fixture = fixture
        return json.loads(require_file(path=path, file_name='{}_template.json'.format(fixture)))

    def records(self, record):
        # remember effective status pk for reference at initial "all" role
        if self.fixture == 'status':
            if record['fields']['status'] == 'productive':
                self.status = record['pk']
        # gather all permission pks
        if self.fixture == 'permissions':
            self.permissions = record['fields']['key']
        fields = dict(record['fields'])
        return fields

    def generate_fixtures_basics(self, path, fixture, hash_sequence):
        fixtures = self.load_fixture(path=path, fixture=fixture)
        for record in fixtures:
            # add uuid TODO #1 uuid shall be compatible with postgres that is not saving as char(32), but uuid field
            record['pk'] = str(python_uuid.uuid4())
            fields = self.records(record)
            to_hash = generate_to_hash(fields=fields, hash_sequence=hash_sequence, unique_id=record['pk'])
            record['fields']['checksum'] = generate_checksum(to_hash)
        with open(path + '{}.json'.format(fixture), 'w') as outfile:
            json.dump(fixtures, outfile)

    def generate_fixtures_roles(self, path, fixture, hash_sequence):
        fixtures = self.load_fixture(path=path, fixture=fixture)
        for record in fixtures:
            record['pk'] = str(python_uuid.uuid4())
            fields = self.records(record)
            # add uuid TODO #1 uuid shall be compatible with postgres that is not saving as char(32), but uuid field
            record['fields']['lifecycle_id'] = str(python_uuid.uuid4())
            # relations
            record['fields']['status_id'] = self.status
            fields['status_id'] = self.status
            # valid from
            now = timezone.now()
            record['fields']['valid_from'] = str(now)
            fields['valid_from'] = str(now)
            # permissions
            record['fields']['permissions'] = self.permissions[:-1]
            fields['permissions'] = self.permissions[:-1]
            to_hash = generate_to_hash(fields=fields, hash_sequence=hash_sequence, unique_id=record['pk'],
                                       lifecycle_id=record['fields']['lifecycle_id'])
            record['fields']['checksum'] = generate_checksum(to_hash)
        with open(path + '{}.json'.format(fixture), 'w') as outfile:
            json.dump(fixtures, outfile)


fix = Fixtures()
fix.generate_fixtures_basics(path=FIXTURES_DIR_BASIC, fixture='status', hash_sequence=['status'])
fix.generate_fixtures_basics(path=FIXTURES_DIR_URP, fixture='permissions', hash_sequence=['key', 'dialog',
                                                                                          'permission'])
fix.generate_fixtures_roles(path=FIXTURES_DIR_URP, fixture='roles', hash_sequence=['role', 'status_id', 'version',
                                                                                   'valid_from', 'valid_to',
                                                                                   'permissions'])
