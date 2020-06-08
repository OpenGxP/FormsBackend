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

# python imports
import requests
import json
import uuid as python_uuid
import threading
import logging

# app imports
from urp.models.webhooks import WebHooks
from urp.serializers.webhooksmonitor import WebHooksMonitorReadWriteSerializer

# define logger
logger = logging.getLogger(__name__)


class WebHooksRouter(object):
    def __init__(self, request, instance):
        self.request = request
        self.instance = instance
        self.headers = {'Accept': 'application/json',
                        'Content-Type': 'application/json',
                        'Authorization': ''}
        self.payload = self.build_payload
        self.hooks = self.build_hooks

    @property
    def build_payload(self):
        payload = {}
        field_values = self.instance.linked_fields_values
        for record in field_values:
            payload[record.field] = record.value
        return payload

    @property
    def build_hooks(self):
        return WebHooks.objects.get_prod_valid_list({'form': self.instance.form})

    def start(self):
        for hook in self.hooks:
            headers = self.headers.copy()
            headers['Authorization'] = '{} {}'.format(hook.header_token, hook.decrypt_token)
            t = threading.Thread(target=self.call, kwargs={'url': hook.url, 'headers': headers})
            t.start()

    def call(self, url, headers):
        response = requests.post(url=url, headers=headers, data=json.dumps(self.payload))
        data = {'key': python_uuid.uuid4(),
                'url': url,
                'payload': json.dumps(self.payload),
                'status_code': response.status_code,
                'response': response.text}
        ser = WebHooksMonitorReadWriteSerializer(data=data, context={'method': 'POST',
                                                                     'function': 'new',
                                                                     'user': self.request.user.username,
                                                                     'validate_only': True})
        if ser.is_valid():
            ser.save()
        else:
            logger.error(ser.errors)
        return
