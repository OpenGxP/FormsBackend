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

# django imports
from django.db import models
from django.utils.translation import gettext_lazy as _

# app imports
from basics.models import GlobalModel, GlobalManager, CHAR_DEFAULT, Status, LOG_HASH_SEQUENCE, FIELD_VERSION, \
    GlobalModelLog
from urp.models.tags import Tags
from urp.models.workflows.workflows import Workflows
from urp.validators import validate_no_space, validate_no_specials_reduced, validate_no_numbers, validate_only_ascii, \
    SPECIALS_REDUCED
from urp.models.forms.sub.sections import FormsSections
from urp.models.forms.sub.text_fields import FormsTextFields
from urp.models.forms.sub.bool_fields import FormsBoolFields


# log manager
class FormsLogManager(GlobalManager):
    # flags
    HAS_VERSION = False
    HAS_STATUS = False
    IS_LOG = True

    # meta
    GET_MODEL_ORDER = ('form',
                       'workflow',
                       'tag',)


# log table
class FormsLog(GlobalModelLog):
    # custom fields
    form = models.CharField(_('Form'), max_length=CHAR_DEFAULT)
    workflow = models.CharField(_('Workflow'), max_length=CHAR_DEFAULT)
    tag = models.CharField(_('Tag'), max_length=CHAR_DEFAULT, blank=True)
    # defaults
    status = models.ForeignKey(Status, on_delete=models.PROTECT, verbose_name=_('Status'))
    version = FIELD_VERSION

    # manager
    objects = FormsLogManager()

    # integrity check
    def verify_checksum(self):
        to_hash_payload = 'form:{};workflow:{};tag:{};status_id:{};version:{};valid_from:{};valid_to:{};'. \
            format(self.form, self.workflow, self.tag, self.status_id, self.version, self.valid_from, self.valid_to)
        return self._verify_checksum(to_hash_payload=to_hash_payload)

    @property
    def get_status(self):
        return self.status.status

    # hashing
    HASH_SEQUENCE = LOG_HASH_SEQUENCE + ['form', 'workflow', 'tag', 'status_id', 'version', 'valid_from', 'valid_to']

    # permissions
    MODEL_ID = '29'
    MODEL_CONTEXT = 'FormsLog'

    class Meta:
        unique_together = None


# manager
class FormsManager(GlobalManager):
    # flags
    LOG_TABLE = FormsLog
    WF_MGMT = True

    # meta
    GET_MODEL_ORDER = ('form',
                       'workflow',
                       'tag')

    def meta(self, data):
        self.meta_sub(data=data)


# table
class Forms(GlobalModel):
    # custom fields
    form = models.CharField(_('Form'), max_length=CHAR_DEFAULT, validators=[validate_no_specials_reduced,
                                                                            validate_no_space,
                                                                            validate_no_numbers,
                                                                            validate_only_ascii],
                            help_text=_('Special characters "{}" are not '
                                        'permitted. No whitespaces and numbers.'
                                        .format(SPECIALS_REDUCED)))
    workflow = models.CharField(_('Workflow'), max_length=CHAR_DEFAULT, help_text=_('Select workflow.'))
    tag = models.CharField(_('Tag'), max_length=CHAR_DEFAULT, blank=True, help_text=_('Select tag.'))
    # defaults
    status = models.ForeignKey(Status, on_delete=models.PROTECT, verbose_name=_('Status'))
    version = FIELD_VERSION

    # integrity check
    def verify_checksum(self):
        to_hash_payload = 'form:{};workflow:{};tag:{};status_id:{};version:{};valid_from:{};valid_to:{};'. \
            format(self.form, self.workflow, self.tag, self.status_id, self.version, self.valid_from, self.valid_to)
        return self._verify_checksum(to_hash_payload=to_hash_payload)

    @property
    def get_status(self):
        return self.status.status

    @property
    def linked_sections(self):
        return FormsSections.objects.filter(lifecycle_id=self.lifecycle_id, version=self.version).all()

    @property
    def linked_sections_values(self):
        return FormsSections.objects.filter(lifecycle_id=self.lifecycle_id, version=self.version).values()

    @property
    def linked_fields_text(self):
        return FormsTextFields.objects.filter(lifecycle_id=self.lifecycle_id, version=self.version).all()

    @property
    def linked_fields_text_values(self):
        return FormsTextFields.objects.filter(lifecycle_id=self.lifecycle_id, version=self.version).values()

    @property
    def linked_fields_bool(self):
        return FormsBoolFields.objects.filter(lifecycle_id=self.lifecycle_id, version=self.version).all()

    @property
    def linked_fields_bool_values(self):
        return FormsBoolFields.objects.filter(lifecycle_id=self.lifecycle_id, version=self.version).values()

    def delete_me(self):
        FormsSections.objects.filter(lifecycle_id=self.lifecycle_id, version=self.version).delete()
        FormsTextFields.objects.filter(lifecycle_id=self.lifecycle_id, version=self.version).delete()
        FormsBoolFields.objects.filter(lifecycle_id=self.lifecycle_id, version=self.version).delete()
        self.delete()

    @staticmethod
    def sub_tables():
        return {FormsSections: 'linked_sections',
                FormsTextFields: 'linked_fields_text',
                FormsBoolFields: 'linked_fields_bool'}

    def fields_execution(self):
        data = list()
        data.append(FormsTextFields.objects.filter(lifecycle_id=self.lifecycle_id,
                                                   version=self.version).all())
        data.append(FormsBoolFields.objects.filter(lifecycle_id=self.lifecycle_id,
                                                   version=self.version).all())
        return data

    # manager
    objects = FormsManager()

    # hashing
    HASH_SEQUENCE = ['form', 'workflow', 'tag', 'status_id', 'version', 'valid_from', 'valid_to']

    # permissions
    MODEL_ID = '28'
    MODEL_CONTEXT = 'Forms'

    # unique field
    UNIQUE = 'form'

    class Meta:
        unique_together = ('lifecycle_id', 'version')

    # lookup fields
    LOOKUP = {'tag': {'model': Tags,
                      'key': 'tag',
                      'multi': False,
                      'method': 'select'},
              'workflow': {'model': Workflows,
                           'key': 'workflow',
                           'multi': False,
                           'method': 'select'}}
