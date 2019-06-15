"""
opengxp.org
Copyright (C) 2019 Henrik Baran

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
from django.urls import reverse
from django.conf import settings

# app imports
from ..models import Email
from ..serializers import EmailReadWriteSerializer

# test imports
from . import Prerequisites, GetAll, PostNew, DeleteOneNoStatus, PatchOneNoStatus, GetOneNoStatus

# basic imports
from basics.custom import require_json_file


BASE_PATH = reverse('email-list')
EMAIL_CON_DATA = require_json_file(path=settings.SECURITY_DIR + '/credentials/', file_name='EMAIL_CON_DATA.json')


# get
class GetAllEmail(GetAll):
    def __init__(self, *args, **kwargs):
        super(GetAllEmail, self).__init__(*args, **kwargs)
        self.base_path = BASE_PATH
        self.model = Email
        self.serializer = EmailReadWriteSerializer
        self.execute = True


class GetOneNoStatusEmail(GetOneNoStatus):
    def __init__(self, *args, **kwargs):
        super(GetOneNoStatusEmail, self).__init__(*args, **kwargs)
        self.base_path = BASE_PATH
        self.prerequisites = Prerequisites(base_path=self.base_path)
        self.model = Email
        self.serializer = EmailReadWriteSerializer
        self.execute = True
        self.ok_object_data = EMAIL_CON_DATA
        self.ok_object_data_unique = 'host'


# post
class PostNewEmail(PostNew):
    def __init__(self, *args, **kwargs):
        super(PostNewEmail, self).__init__(*args, **kwargs)
        self.base_path = BASE_PATH
        self.model = Email
        self.prerequisites = Prerequisites(base_path=self.base_path)
        self.valid_payload = EMAIL_CON_DATA
        invalid_payload = EMAIL_CON_DATA.copy()
        invalid_payload['host'] = ''
        self.invalid_payloads = [dict(), invalid_payload]
        self.execute = True
        self.status = False


# delete
class DeleteOneEmail(DeleteOneNoStatus):
    def __init__(self, *args, **kwargs):
        super(DeleteOneEmail, self).__init__(*args, **kwargs)
        self.base_path = BASE_PATH
        self.model = Email
        self.prerequisites = Prerequisites(base_path=self.base_path)
        self.serializer = EmailReadWriteSerializer
        self.ok_object_data = EMAIL_CON_DATA
        self.ok_object_data_unique = 'host'
        self.execute = True


# patch
class PatchOneEmail(PatchOneNoStatus):
    def __init__(self, *args, **kwargs):
        super(PatchOneEmail, self).__init__(*args, **kwargs)
        self.base_path = BASE_PATH
        self.model = Email
        self.prerequisites = Prerequisites(base_path=self.base_path)
        self.serializer = EmailReadWriteSerializer
        self.ok_object_data_unique = 'host'
        self.ok_object_data = EMAIL_CON_DATA
        valid_payload = EMAIL_CON_DATA.copy()
        valid_payload['priority'] = 2
        self.valid_payload = valid_payload
        invalid_payload = EMAIL_CON_DATA.copy()
        invalid_payload['host'] = ''
        self.invalid_payload = invalid_payload
        self.execute = True
