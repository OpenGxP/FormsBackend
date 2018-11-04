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

# app imports
from forms.settings import require_file, BASE_DIR

# app imports
from basics.custom import generate_checksum, generate_to_hash

# fixtures dir
FIXTURES_DIR_URP = os.path.join(BASE_DIR, 'urp/fixtures/')
FIXTURES_DIR_BASIC = os.path.join(BASE_DIR, 'basics/fixtures/')


def generate_fixture(path, fixture, hash_sequence, hash_sequence_mtm=None):
    fixtures = json.loads(require_file(path=path, file_name='{}_template.json'.format(fixture)))
    fields = dict()
    for record in fixtures:
        for field in record['fields']:
            if field != 'checksum':
                fields[field] = record['fields'][field]
        to_hash = generate_to_hash(fields, hash_sequence=hash_sequence, hash_sequence_mtm=hash_sequence_mtm,
                                   record_id=record['pk'], fixtures=True)
        record['fields']['checksum'] = generate_checksum(to_hash)

    with open(path + '{}.json'.format(fixture), 'w') as outfile:
        json.dump(fixtures, outfile)


# status
generate_fixture(path=FIXTURES_DIR_BASIC, fixture='status', hash_sequence=['status'])
# permissions
generate_fixture(path=FIXTURES_DIR_URP, fixture='permissions', hash_sequence=['permission'])
# roles
generate_fixture(path=FIXTURES_DIR_URP, fixture='roles', hash_sequence=['role', 'status_id', 'version'],
                 hash_sequence_mtm=['permissions', 'sod_roles'])
