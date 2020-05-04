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

# rest imports
from rest_framework import serializers

# django imports
from django.conf import settings

# app imports
from basics.models import CHAR_DEFAULT, Status
from urp.models.forms.forms import Forms, FormsLog
from urp.models.tags import Tags
from urp.fields import SectionsField, TextField, BoolField
from urp.models.workflows.workflows import Workflows
from urp.models.roles import Roles
from urp.serializers import GlobalReadWriteSerializer
from urp.custom import create_log_record
from urp.models.users import Users
from urp.custom import create_signatures_record
from basics.custom import render_email_from_template
from urp.backends.Email import send_email
from urp.models.inbox import Inbox
from urp.models.logs.signatures import SignaturesLog
from urp.models.forms.sub.sections import FormsSectionsLog
from urp.models.forms.sub.text_fields import FormsTextFieldsLog
from urp.models.forms.sub.bool_fields import FormsBoolFieldsLog
from urp.execptions import DummyException


FORM_FIELDS = ('sections', 'fields_text', 'fields_bool', )


# read / add / edit
class FormsReadWriteSerializer(GlobalReadWriteSerializer):
    sections = SectionsField(source='linked_sections')
    fields_text = TextField(source='linked_fields_text', required=False)
    fields_bool = BoolField(source='linked_fields_bool', required=False)

    status = serializers.CharField(source='get_status', read_only=True)

    class Meta:
        model = Forms
        extra_kwargs = {'version': {'required': False}}
        fields = model.objects.GET_MODEL_ORDER + FORM_FIELDS + model.objects.GET_BASE_ORDER_STATUS_MANAGED + \
            model.objects.GET_BASE_CALCULATED + model.objects.COMMENT_SIGNATURE

    def validate_tag(self, value):
        if value:
            allowed = Tags.objects.get_by_natural_key_productive_list('tag')
            if value not in allowed:
                raise serializers.ValidationError('Not allowed to use "{}".'.format(value))
        return value

    def validate_workflow(self, value):
        if value:
            allowed = Workflows.objects.get_by_natural_key_productive_list('workflow')
            if value not in allowed:
                raise serializers.ValidationError('Not allowed to use "{}".'.format(value))
        return value

    def validate_post_specific(self, data):
        # validate that any field type is present
        check = ['linked_fields_text', 'linked_fields_bool']
        if set(check).issubset(data):
            flag = False
            for x in data:
                if x in check:
                    if data[x]:
                        flag = True
                        break
            if not flag:
                self.my_errors.update({'fields_text': ['At least one field must be available.']})
                self.my_errors.update({'fields_bool': ['At least one field must be available.']})
        else:
            for p in self.sub_parents:
                # validate sequence unique characteristic within parent
                if len(self.global_sequence_check[p]) != len(set(self.global_sequence_check[p])):
                    raise serializers.ValidationError('Sequence within one section must be unique.')

    def validate_sections(self, value):
        error_dict = {}
        if not value:
            raise serializers.ValidationError('At least one section ist required.')
        self.validate_sequence_plain(value)
        try:
            value = self.validate_sub(value, key='section', parent=True)
        except serializers.ValidationError as e:
            error_dict.update(e.detail)

        self.validate_predecessors(value, key='section')
        allowed_roles = Roles.objects.get_by_natural_key_productive_list('role')

        for item in value:
            # validate role field
            if 'role' not in item.keys():
                self.create_update_record(error_dict=error_dict, item=item, value={'role': ['This field is required.']})
            elif not item['role']:
                self.create_update_record(error_dict=error_dict, item=item, value={'role': ['This field is required.']})
            elif not isinstance(item['role'], str):
                self.create_update_record(error_dict=error_dict, item=item,
                                          value={'role': ['This field requires data type string.']})
            elif item['role'] not in allowed_roles:
                self.create_update_record(error_dict=error_dict, item=item,
                                          value={'role': ['Not allowed to use "{}".'.format(item['role'])]})

            # validate confirmation field
            if 'confirmation' not in item.keys():
                self.create_update_record(error_dict=error_dict, item=item,
                                          value={'confirmation': ['This field is required.']})
            elif not item['confirmation']:
                self.create_update_record(error_dict=error_dict, item=item,
                                          value={'confirmation': ['This field is required.']})
            elif item['confirmation'] not in settings.DEFAULT_LOG_CONFIRMATIONS:
                allowed = ''
                for i in settings.DEFAULT_LOG_CONFIRMATIONS:
                    allowed += '"{}", '.format(i)
                self.create_update_record(error_dict=error_dict, item=item,
                                          value={'confirmation': ['Only {} are allowed.'.format(allowed[:-2])]})

        if error_dict:
            raise serializers.ValidationError(error_dict)

        return value

    def validate_fields_text(self, value):
        error_dict = {}
        self.validate_sequence_plain(value, form=True)
        try:
            value = self.validate_sub(value, key='field')
        except serializers.ValidationError as e:
            error_dict.update(e.detail)

        try:
            value = self.validated_form_fields(value)
        except serializers.ValidationError as e:
            error_dict.update(e.detail)

        for item in value:
            # validate default field
            if 'default' in item.keys():
                if not isinstance(item['default'], str):
                    self.create_update_record(error_dict=error_dict, item=item,
                                              value={'default': ['This field requires data type string.']})
                elif len(item['default']) > CHAR_DEFAULT:
                    self.create_update_record(error_dict=error_dict, item=item,
                                              value={'instruction': ['This field must not be longer than {} characters.'
                                                     .format(CHAR_DEFAULT)]})

        if error_dict:
            raise serializers.ValidationError(error_dict)

        return value

    def validate_fields_bool(self, value):
        error_dict = {}
        self.validate_sequence_plain(value, form=True)

        try:
            value = self.validate_sub(value, key='field')
        except serializers.ValidationError as e:
            error_dict.update(e.detail)

        try:
            value = self.validated_form_fields(value)
        except serializers.ValidationError as e:
            error_dict.update(e.detail)

        for item in value:
            # validate default field
            if 'default' in item.keys():
                if not isinstance(item['default'], bool):
                    self.create_update_record(error_dict=error_dict, item=item,
                                              value={'default': ['This field requires data type boolean.']})

        if error_dict:
            raise serializers.ValidationError(error_dict)

        return value

    def create_specific(self, validated_data, obj):
        for table, key in obj.sub_tables().items():
            self.model.objects.create_sub_record(obj=obj, validated_data=validated_data, key=key,
                                                 sub_model=table)
        return validated_data, obj

    def update_specific(self, validated_data, instance, self_call=None):
        self.update_sub(validated_data, instance)
        return validated_data, instance


# new version / status
class FormsNewVersionStatusSerializer(GlobalReadWriteSerializer):
    sections = SectionsField(source='linked_sections', read_only=True)
    fields_text = TextField(source='linked_fields_text', read_only=True)
    fields_bool = BoolField(source='linked_fields_bool', read_only=True)
    status = serializers.CharField(source='get_status', read_only=True)

    class Meta:
        model = Forms
        extra_kwargs = {'version': {'required': False},
                        'form': {'required': False},
                        'workflow': {'required': False},
                        'tag': {'required': False}}
        fields = model.objects.GET_MODEL_ORDER + FORM_FIELDS + model.objects.GET_BASE_ORDER_STATUS_MANAGED + \
            model.objects.GET_BASE_CALCULATED + model.objects.COMMENT_SIGNATURE

    def create_specific(self, validated_data, obj):
        for table, key in obj.sub_tables().items():
            validated_data[key] = getattr(self.instance, '{}_values'.format(key))
            self.model.objects.create_sub_record(obj=obj, validated_data=validated_data, key=key,
                                                 sub_model=table, new_version=True, instance=self.instance)
        return validated_data, obj

    # FO-251: route self_call
    def update_specific(self, validated_data, instance, self_call=None):
        if self.context['workflow'] and not self_call:
            # workflow start
            if self.context['status'] == 'circulation':
                # get role(s) that do not have any predecessor (must be root steps)
                base_steps = self.context['workflow']['workflow'].linked_steps_root
                emails = []
                users = []
                for st in base_steps:
                    users_per_role = Users.objects.get_all_by_role(st.role)
                    for record in users_per_role:
                        emails.append(record.email)
                        users.append(record.username)
                # remove duplicates
                emails = list(set(emails))
                users = list(set(users))

                # send email, do nothing else
                email_data = {'context': self.model.MODEL_CONTEXT,
                              'object': getattr(self.instance, self.model.UNIQUE),
                              'version': self.instance.version,
                              'url': '{}/#/md/{}/{}/{}/productive'.format(settings.EMAIL_BASE_URL,
                                                                          self.model.MODEL_CONTEXT.lower(),
                                                                          self.instance.lifecycle_id,
                                                                          self.instance.version)}

                # create signatures record for start circulation
                create_signatures_record(workflow=self.context['workflow']['workflow'],
                                         user=self.context['user'],
                                         timestamp=self.now,
                                         context=self.model.MODEL_CONTEXT,
                                         obj=self.instance,
                                         step=self.context['workflow']['step'],
                                         sequence=self.context['workflow']['sequence'],
                                         cycle=self.context['workflow']['cycle'],
                                         action=self.context['workflow']['action'])

                html_message = render_email_from_template(template_file_name='email_workflow.html',
                                                          data=email_data)
                send_email(subject='OpenGxP Workflow Action', html_message=html_message, email=emails)
                # create inbox record
                email_data['lifecycle_id'] = self.instance.lifecycle_id
                email_data['users'] = users
                del email_data['url']
                Inbox.objects.create(data=email_data)

            if self.context['status'] == 'productive':
                self.context['status'] = 'circulation'
                validated_data['status_id'] = Status.objects.status_by_text(self.context['status'])
                create_signatures_record(workflow=self.context['workflow']['workflow'],
                                         user=self.context['user'],
                                         timestamp=self.now,
                                         context=self.model.MODEL_CONTEXT,
                                         obj=self.instance,
                                         step=self.context['workflow']['step'],
                                         sequence=self.context['workflow']['sequence'],
                                         cycle=self.context['workflow']['cycle'],
                                         action=self.context['workflow']['action'])

                # get history after writing signatures record
                history = SignaturesLog.objects.filter(
                    object_lifecycle_id=self.instance.lifecycle_id, cycle=self.context['workflow']['cycle'],
                    object_version=self.instance.version,
                    action=settings.DEFAULT_LOG_WF_WORKFLOW).order_by('-timestamp').all()

                # pass history to next steps method
                next_steps = self.context['workflow']['workflow'].linked_steps_next_incl_parallel(
                    history=history)

                # last step of workflow performed
                if not next_steps:
                    # FO-234: set valid from at last step, if not yet set
                    if not self.instance.valid_from:
                        validated_data['valid_from'] = self.now
                    # Fo-251: call previous version method
                    if self.instance.version > 1:
                        self.update_previous_version_valid_to()
                    self.context['status'] = 'productive'
                    validated_data['status_id'] = Status.objects.status_by_text(self.context['status'])
                    # FO-243: delete inbox record, because workflow is done
                    Inbox.objects.delete(lifecycle_id=self.instance.lifecycle_id, version=self.instance.version)
                else:
                    emails = []
                    users = []
                    for st in next_steps:
                        users_per_role = Users.objects.get_all_by_role(st.role)
                        for record in users_per_role:
                            emails.append(record.email)
                            users.append(record.username)
                    # remove duplicates
                    emails = list(set(emails))
                    users = list(set(users))

                    # send email, do nothing else
                    email_data = {'context': self.model.MODEL_CONTEXT,
                                  'object': getattr(self.instance, self.model.UNIQUE),
                                  'version': self.instance.version,
                                  'url': '{}/#/md/{}/{}/{}/productive'.format(settings.EMAIL_BASE_URL,
                                                                              self.model.MODEL_CONTEXT.lower(),
                                                                              self.instance.lifecycle_id,
                                                                              self.instance.version)}
                    html_message = render_email_from_template(template_file_name='email_workflow.html',
                                                              data=email_data)
                    send_email(subject='OpenGxP Workflow Action', html_message=html_message, email=emails)
                    # create inbox record
                    email_data['lifecycle_id'] = self.instance.lifecycle_id
                    email_data['users'] = users
                    del email_data['url']
                    Inbox.objects.delete(lifecycle_id=self.instance.lifecycle_id, version=self.instance.version)
                    Inbox.objects.create(data=email_data)

            if self.context['status'] == 'draft':
                # delete all inbox records because back in draft
                Inbox.objects.delete(lifecycle_id=self.instance.lifecycle_id, version=self.instance.version)

                # create signatures record for set back on draft
                create_signatures_record(workflow=self.context['workflow']['workflow'],
                                         user=self.context['user'],
                                         timestamp=self.now,
                                         context=self.model.MODEL_CONTEXT,
                                         obj=self.instance,
                                         step=self.context['workflow']['step'],
                                         sequence=self.context['workflow']['sequence'],
                                         cycle=self.context['workflow']['cycle'],
                                         action=self.context['workflow']['action'])

        return validated_data, instance


# delete
class FormsDeleteSerializer(GlobalReadWriteSerializer):
    class Meta:
        model = Forms
        fields = model.objects.COMMENT_SIGNATURE

    def delete_specific(self, fields):
        for table, key in self.instance.sub_tables().items():
            linked_records = getattr(self.instance, '{}_values'.format(key))
            for record in linked_records:
                create_log_record(model=table, context=self.context, obj=self.instance, now=self.now,
                                  validated_data=record, action=settings.DEFAULT_LOG_DELETE,
                                  signature=self.signature, central=False)
        return fields


# read logs
class FormsLogReadSerializer(GlobalReadWriteSerializer):
    status = serializers.CharField(source='get_status', read_only=True)

    class Meta:
        model = FormsLog
        fields = model.objects.GET_MODEL_ORDER + model.objects.GET_BASE_ORDER_STATUS_MANAGED + \
            model.objects.GET_BASE_ORDER_LOG + model.objects.GET_BASE_CALCULATED


# read logs sections
class FormsSectionsLogReadSerializer(GlobalReadWriteSerializer):
    class Meta:
        model = FormsSectionsLog
        fields = model.objects.GET_MODEL_ORDER + model.objects.GET_BASE_ORDER_SUB + \
            model.objects.GET_BASE_ORDER_LOG + model.objects.GET_BASE_CALCULATED


# read logs text
class FormsTextFieldsLogReadSerializer(GlobalReadWriteSerializer):
    class Meta:
        model = FormsTextFieldsLog
        fields = model.objects.GET_MODEL_ORDER + model.objects.GET_BASE_ORDER_SUB + \
            model.objects.GET_BASE_ORDER_LOG + model.objects.GET_BASE_CALCULATED


# read logs bool
class FormsBoolFieldsLogReadSerializer(GlobalReadWriteSerializer):
    class Meta:
        model = FormsBoolFieldsLog
        fields = model.objects.GET_MODEL_ORDER + model.objects.GET_BASE_ORDER_SUB + \
            model.objects.GET_BASE_ORDER_LOG + model.objects.GET_BASE_CALCULATED
