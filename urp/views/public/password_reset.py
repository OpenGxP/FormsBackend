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

# python imports
from uuid import UUID

# rest imports
from rest_framework.response import Response
from rest_framework import serializers
from rest_framework.decorators import api_view
from rest_framework import status as http_status

# app imports
from urp.models import Tokens, Users, Vault
from urp.backends.User import activate_user
from basics.custom import render_email_from_template
from basics.models import Status
from urp.vault import validate_password_input, create_update_vault
from urp.backends.Email import send_email

# django imports
from django.utils import timezone
from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.contrib.auth.hashers import check_password
from django.views.decorators.csrf import csrf_exempt


@api_view(['POST'])
@csrf_exempt
def request_password_reset_email_view(request):
    # data and field validation
    if not hasattr(request, 'data'):
        raise serializers.ValidationError('Field "email" is required.')
    if 'email' not in request.data:
        raise serializers.ValidationError('Field "email" is required.')
    email = request.data['email']

    # validate email string in general, no check if this email is used, but just a valid mail address
    try:
        validate_email(email)
    except ValidationError as e:
        raise serializers.ValidationError(e.message)

    # check if account with this email available
    user = Users.objects.get_valid_user_by_email(email)
    if user:
        # create token and send email with token url
        token = Tokens.objects.create_token(username=user.username, email=email)
        data = {'fullname': user.get_full_name(),
                'url': '{}/#/password_reset_email/{}'.format(settings.EMAIL_BASE_URL, token.id),
                'expiry_timestamp': token.expiry_timestamp}
        html_message = render_email_from_template(template_file_name='email_password_reset_ok.html', data=data)
    else:
        html_message = render_email_from_template(template_file_name='email_password_reset_nok.html')

    send_email(subject='OpenGxP Password Reset', html_message=html_message, email=email)

    # 100% positive inform requester that email was send
    return Response(data=['Email has been sent.'], status=http_status.HTTP_200_OK)


@api_view(['GET', 'POST'])
def password_reset_email_view(request, token):
    @csrf_exempt
    def post(_request):
        # data and field validation
        if not hasattr(request, 'data'):
            raise serializers.ValidationError('Fields "token", "password_new" and "password_new_verification" '
                                              'are required.')

        error_dict = dict()
        field_error = ['This filed is required.']

        if 'password_new' not in request.data:
            error_dict['password_new'] = field_error
        if 'password_new_verification' not in request.data:
            error_dict['password_new_verification'] = field_error

        # validate if at least one question is answered
        flag = False
        question_answer_fields = vault.question_answers_fields()
        for answer in question_answer_fields.values():
            if answer in request.data:
                flag = True
                break

        if not flag:
            error_dict['answer_one'] = 'At least one answer field is required.'
            error_dict['answer_two'] = 'At least one answer field is required.'
            error_dict['answer_three'] = 'At least one answer field is required.'

        if error_dict:
            raise serializers.ValidationError(error_dict)

        # validate security questions
        answers = vault.get_answers
        for answer in question_answer_fields.values():
            if answer in request.data:
                raw_answer = request.data[answer]
                if not check_password(raw_answer, answers[answer]):
                    error = {answer: 'Security question was not answered correctly.'}
                    raise serializers.ValidationError(error)

        # validate password data
        validate_password_input(request.data)

        # FO-147: new password can not be equal to previous password
        raw_pw = request.data['password_new']
        if check_password(raw_pw, vault.password):
            raise serializers.ValidationError('New password is identical to old password. Password must be changed.')

        # update vault with new password
        now = timezone.now()
        create_update_vault(data=request.data, instance=vault, action=settings.DEFAULT_LOG_PASSWORD,
                            user=vault.username, now=now, self_pw=True)

        # in case user is in status blocked, set effective
        user = Users.objects.get_valid_by_key(vault.username)
        if user.status.id == Status.objects.blocked:
            activate_user(user=user, action_user=user.username, now=now)

        # inform user about successful password change
        email_data = {'fullname': user.get_full_name()}
        html_message = render_email_from_template(template_file_name='email_password_changed.html', data=email_data)
        send_email(subject='OpenGxP Password Changed', html_message=html_message, email=token.email)

        # delete token
        token.delete()

        return Response(status=http_status.HTTP_200_OK)

    def get(_request):
        # return questions to be answered
        questions = vault.get_questions
        return Response(data=questions, status=http_status.HTTP_200_OK)

    try:
        uuid_token = UUID(token)
    except ValueError:
        return Response(status=http_status.HTTP_400_BAD_REQUEST)

    try:
        token = Tokens.objects.get(id=uuid_token)
        # check if token exists and is valid
        if not Tokens.objects.check_token_valid(token=uuid_token):
            raise serializers.ValidationError('Token is expired. Please request new password reset.')

        # get user instance
        vault = Vault.objects.get(username=token.username)

    except Tokens.DoesNotExist:
        return Response(status=http_status.HTTP_404_NOT_FOUND)
    except ValidationError:
        return Response(status=http_status.HTTP_400_BAD_REQUEST)

    if request.method == 'GET':
        return get(request)
    if request.method == 'POST':
        return post(request)
