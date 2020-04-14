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
from urp.models.workflows.sub.steps import WorkflowsSteps
from urp.validators import validate_no_space, validate_no_specials_reduced, validate_no_numbers, validate_only_ascii, \
    SPECIALS_REDUCED


# log manager
class WorkflowsLogManager(GlobalManager):
    # flags
    HAS_VERSION = False
    HAS_STATUS = False
    IS_LOG = True

    # meta
    GET_MODEL_ORDER = ('workflow',
                       'tag',)


# log table
class WorkflowsLog(GlobalModelLog):
    # custom fields
    workflow = models.CharField(_('Workflow'), max_length=CHAR_DEFAULT)
    tag = models.CharField(_('Tag'), max_length=CHAR_DEFAULT, blank=True)
    # defaults
    status = models.ForeignKey(Status, on_delete=models.PROTECT)
    version = FIELD_VERSION

    # manager
    objects = WorkflowsLogManager()

    # integrity check
    def verify_checksum(self):
        to_hash_payload = 'workflow:{};tag:{};status_id:{};version:{};valid_from:{};valid_to:{};'. \
            format(self.workflow, self.tag, self.status_id, self.version, self.valid_from, self.valid_to)
        return self._verify_checksum(to_hash_payload=to_hash_payload)

    @property
    def get_status(self):
        return self.status.status

    # hashing
    HASH_SEQUENCE = LOG_HASH_SEQUENCE + ['workflow', 'tag', 'status_id', 'version', 'valid_from', 'valid_to']

    # permissions
    MODEL_ID = '27'
    MODEL_CONTEXT = 'WorkflowsLog'

    class Meta:
        unique_together = None


# manager
class WorkflowsManager(GlobalManager):
    # flags
    LOG_TABLE = WorkflowsLog

    # meta
    GET_MODEL_ORDER = ('workflow',
                       'tag')

    def meta(self, data):
        self.meta_sub(data=data)


# table
class Workflows(GlobalModel):
    # custom fields
    workflow = models.CharField(_('Workflow'), max_length=CHAR_DEFAULT,
                                validators=[validate_no_specials_reduced,
                                            validate_no_space,
                                            validate_no_numbers,
                                            validate_only_ascii],
                                help_text=_('Special characters "{}" are not '
                                            'permitted. No whitespaces and numbers.'
                                            .format(SPECIALS_REDUCED)))
    tag = models.CharField(_('Tag'), max_length=CHAR_DEFAULT, blank=True, help_text=_('Select tag.'))
    # defaults
    status = models.ForeignKey(Status, on_delete=models.PROTECT)
    version = FIELD_VERSION

    # integrity check
    def verify_checksum(self):
        to_hash_payload = 'workflow:{};tag:{};status_id:{};version:{};valid_from:{};valid_to:{};'. \
            format(self.workflow, self.tag, self.status_id, self.version, self.valid_from, self.valid_to)
        return self._verify_checksum(to_hash_payload=to_hash_payload)

    @property
    def get_status(self):
        return self.status.status

    @property
    def linked_steps(self):
        return WorkflowsSteps.objects.filter(lifecycle_id=self.lifecycle_id, version=self.version).all()

    @property
    def linked_steps_values(self):
        return WorkflowsSteps.objects.filter(lifecycle_id=self.lifecycle_id, version=self.version).values()

    @property
    def linked_steps_roles(self):
        return WorkflowsSteps.objects.filter(lifecycle_id=self.lifecycle_id,
                                             version=self.version).values('step', 'role', 'sequence', 'predecessors')

    @property
    def linked_steps_root(self):
        return WorkflowsSteps.objects.filter(lifecycle_id=self.lifecycle_id, version=self.version,
                                             predecessors__exact='').all()

    def linked_steps_next(self, predecessor):
        steps_next = []
        query = WorkflowsSteps.objects.filter(lifecycle_id=self.lifecycle_id, version=self.version).all()
        for record in query:
            if predecessor in record.predecessors.split(','):
                steps_next.append(record)
        return steps_next

    def linked_steps_next_incl_parallel(self, history):
        # history is ordered by -timestamp therefore [0] returns last step
        last_step = history[0]
        query = WorkflowsSteps.objects.filter(lifecycle_id=self.lifecycle_id, version=self.version).all()
        remaining_steps = []
        for step in query:
            # loop over all history records, if step is done
            is_in = False
            for record in history:
                if step.step == record.step:
                    is_in = True
                    break
            # only add, if not in history
            if not is_in:
                remaining_steps.append(step)

        # get all of remaining steps that share the same predecessors als the last step
        next_steps = []
        for item in remaining_steps:
            predecessors = WorkflowsSteps.objects.filter(lifecycle_id=self.lifecycle_id, version=self.version,
                                                         step=last_step.step).values_list('predecessors', flat=True)[0]
            if item.predecessors == predecessors:
                next_steps.append(item)

        # if no parallels are lef over, take next steps
        if not next_steps:
            for item in remaining_steps:
                if last_step.step in item.predecessors.split(','):
                    next_steps.append(item)

        return next_steps

    def delete_me(self):
        WorkflowsSteps.objects.filter(lifecycle_id=self.lifecycle_id, version=self.version).delete()
        self.delete()

    @staticmethod
    def sub_tables():
        return {WorkflowsSteps: 'linked_steps'}

    # manager
    objects = WorkflowsManager()

    # hashing
    HASH_SEQUENCE = ['workflow', 'tag', 'status_id', 'version', 'valid_from', 'valid_to']

    # permissions
    MODEL_ID = '26'
    MODEL_CONTEXT = 'Workflows'

    # unique field
    UNIQUE = 'workflow'

    class Meta:
        unique_together = ('lifecycle_id', 'version')

    # lookup fields
    LOOKUP = {'tag': {'model': Tags,
                      'key': 'tag',
                      'multi': False,
                      'method': 'select'}}
