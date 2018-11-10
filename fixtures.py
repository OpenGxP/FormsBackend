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

# fixtures dir
FIXTURES_DIR_URP = os.path.join(BASE_DIR, 'urp/fixtures/')
FIXTURES_DIR_BASIC = os.path.join(BASE_DIR, 'basics/fixtures/')


class Fixtures(object):
    def __init__(self):
        self._permissions = []
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
        self._permissions.append(value)

    @property
    def status(self):
        return self._status

    @status.setter
    def status(self, value):
        for k, v in value.items():
            self._status[k] = v

    def load_fixture(self, path, fixture):
        self.fixture = fixture
        return json.loads(require_file(path=path, file_name='{}_template.json'.format(fixture)))

    def records(self, fixtures, record):
        # add uuid TODO #1 uuid shall be compatible with postgres that is not saving as char(32), but uuid field
        record['fields']['lifecycle_id'] = str(python_uuid.uuid4())
        record['pk'] = str(python_uuid.uuid4())
        ids = {
            'id': record['pk'],
            'lifecycle_id': record['fields']['lifecycle_id']
        }
        # remember effective status pk for reference at initial "all" role
        if self.fixture == 'status':
            # store uuid pks into dict
            self.status = {'status_{}_id'.format(record['fields']['status'].lower()): record['pk']}
        # gather all permission pks
        if self.fixture == 'permissions':
            self.permissions = record['pk']
        # write values on keys in settings
        if self.fixture == 'settings':
            record['fields']['value'] = self.status[record['fields']['key']]
        fields = dict(record['fields'])
        fields.pop('lifecycle_id')
        fields.pop('checksum')
        return fixtures, fields, ids

    def generate_fixtures_basics(self, path, fixture, hash_sequence, hash_sequence_mtm=None):
        fixtures = self.load_fixture(path=path, fixture=fixture)
        for record in fixtures:
            fixtures, fields, ids = self.records(fixtures, record)
            to_hash = generate_to_hash(fields=fields, hash_sequence=hash_sequence, hash_sequence_mtm=hash_sequence_mtm,
                                       ids=ids, fixtures=True)
            record['fields']['checksum'] = generate_checksum(to_hash)

        with open(path + '{}.json'.format(fixture), 'w') as outfile:
            json.dump(fixtures, outfile)

    def generate_fixtures_roles(self, path, fixture, hash_sequence, hash_sequence_mtm=None):
        fixtures = self.load_fixture(path=path, fixture=fixture)
        for record in fixtures:
            fixtures, fields, ids = self.records(fixtures, record)

            # relations
            record['fields']['status_id'] = self.status['status_effective_id']
            fields['status_id'] = self.status['status_effective_id']

            record['fields']['permissions'] = self.permissions
            fields['permissions'] = self.permissions

            to_hash = generate_to_hash(fields=fields, hash_sequence=hash_sequence, hash_sequence_mtm=hash_sequence_mtm,
                                       ids=ids, fixtures=True)
            record['fields']['checksum'] = generate_checksum(to_hash)
        with open(path + '{}.json'.format(fixture), 'w') as outfile:
            json.dump(fixtures, outfile)


fix = Fixtures()
fix.generate_fixtures_basics(path=FIXTURES_DIR_BASIC, fixture='status', hash_sequence=['status'])
fix.generate_fixtures_basics(path=FIXTURES_DIR_URP, fixture='permissions', hash_sequence=['permission'])
fix.generate_fixtures_roles(path=FIXTURES_DIR_URP, fixture='roles', hash_sequence=['role', 'status_id', 'version'],
                            hash_sequence_mtm=['permissions'])

# fixture to fill settings table
fix.generate_fixtures_basics(path=FIXTURES_DIR_BASIC, fixture='settings', hash_sequence=['key', 'value'])
