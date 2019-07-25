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
from functools import wraps
from uuid import UUID

# rest imports
from rest_framework.response import Response
from rest_framework import status as http_status
from rest_framework.decorators import api_view
from rest_framework.reverse import reverse
from rest_framework import serializers

# custom imports
from urp.models import Roles, Permissions, Users, AccessLog, PermissionsLog, RolesLog, UsersLog, LDAP, LDAPLog, \
    SoD, SoDLog, Vault, Tokens, Email, EmailLog, Tags, TagsLog
from urp.serializers import StatusReadWriteSerializer, PermissionsReadWriteSerializer, RolesReadSerializer, \
    RolesWriteSerializer, UsersReadSerializer, RolesDeleteStatusSerializer, RolesNewVersionSerializer, \
    UsersWriteSerializer, UsersNewVersionSerializer, UsersDeleteStatusSerializer, \
    AccessLogReadWriteSerializer, CentralLogReadWriteSerializer, StatusLogReadSerializer, \
    PermissionsLogReadSerializer, RolesLogReadSerializer, UsersLogReadSerializer, AUDIT_TRAIL_SERIALIZERS, \
    LDAPLogReadSerializer, LDAPReadWriteSerializer, LDAPDeleteSerializer, SettingsLogReadSerializer, \
    SettingsReadWriteSerializer, SoDLogReadSerializer, SoDDeleteStatusNewVersionSerializer, SoDWriteSerializer, \
    SoDReadSerializer, UsersPassword, EmailDeleteSerializer, EmailLogReadSerializer, EmailReadWriteSerializer, \
    UserProfile, TagsReadWriteSerializer, TagsDeleteSerializer, TagsLogReadSerializer
from urp.decorators import perm_required, auth_required
from basics.models import Status, StatusLog, CentralLog, SettingsLog, Settings, CHAR_MAX
from basics.custom import get_model_by_string, unique_items, render_email_from_template
from urp.backends.Email import send_email
from urp.backends.User import write_access_log, activate_user
from urp.vault import validate_password_input, create_update_vault

# django imports
from django.core.exceptions import ValidationError
from django.contrib.auth import authenticate, login, logout
from django.utils import timezone
from django.conf import settings
from django.views.decorators.csrf import csrf_protect, ensure_csrf_cookie, csrf_exempt
from django.middleware.csrf import get_token
from django.contrib.auth.hashers import make_password, check_password
from django.contrib.auth.password_validation import password_validators_help_texts
from django.core.validators import validate_email
from django.db.models.base import ModelBase


###############
# AUTO_LOGOUT #
###############

def refresh_time(request, active=True):
    now = timezone.now()
    if now - request.session['last_touch'] > timezone.timedelta(minutes=Settings.objects.core_auto_logout):
        data = {
            'user': request.user.username,
            'timestamp': now,
            'mode': 'automatic',
            'method': Settings.objects.core_devalue,
            'action': settings.DEFAULT_LOG_LOGOUT,
            'attempt': Settings.objects.core_devalue,
            'active': Settings.objects.core_devalue
        }
        logout(request)
        if request.user.is_anonymous:
            write_access_log(data)
    else:
        # only refresh if user was active (default for request)
        if active:
            request.session['last_touch'] = now
        return True


def auto_logout():
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            # use method
            if refresh_time(request=request):
                return view_func(request, *args, **kwargs)
            else:
                return Response(status=http_status.HTTP_401_UNAUTHORIZED)
        return wrapper
    return decorator


@api_view(['PATCH'])
@auth_required(initial_password_check=False)
def logout_auto_view(request):
    if not hasattr(request, 'data'):
        raise serializers.ValidationError('Field "active" required.')
    if 'active' not in request.data:
        raise serializers.ValidationError('Field "active" required.')
    active = request.data['active']
    if not isinstance(active, bool):
        raise serializers.ValidationError('Data type bool required for field "active".')
    if refresh_time(request=request, active=active):
        return Response(status=http_status.HTTP_200_OK)
    else:
        return Response(status=http_status.HTTP_401_UNAUTHORIZED)


########
# ROOT #
########

@api_view(['GET'])
def api_root(request):
    root = {'base': {'root': '/',
                     'subjects': {'login': {'url': reverse('login-view', request=request)},
                                  'csrftoken': {'url': reverse('get_csrf_token', request=request)},
                                  'logout': {'url': reverse('logout-view', request=request)}}},
            'user': {'root': '/user/',
                     'subjects': {'profile': {'url': reverse('user-profile-list', request=request)},
                                  'change_password': {'url': reverse('user-change-password-view', request=request)},
                                  'change_questions': {'url': reverse('user-change-questions-view', request=request)}}},
            'administration': {'root': '/admin/',
                               'subjects': {'roles': {'url': reverse('roles-list', request=request),
                                                      'post': True,
                                                      'patch': True,
                                                      'delete': True,
                                                      'version': True},
                                            'ldap': {'url': reverse('ldap-list', request=request),
                                                     'post': True,
                                                     'patch': True,
                                                     'delete': True,
                                                     'version': False},
                                            'email': {'url': reverse('email-list', request=request),
                                                      'post': True,
                                                      'patch': True,
                                                      'delete': True,
                                                      'version': False},
                                            'users': {'url': reverse('users-list', request=request),
                                                      'post': True,
                                                      'patch': True,
                                                      'delete': True,
                                                      'version': True},
                                            'passwords': {'url': reverse('users-password-list', request=request),
                                                          'post': False,
                                                          'patch': True,
                                                          'delete': False,
                                                          'version': False},
                                            'tags': {'url': reverse('tags-list', request=request),
                                                     'post': True,
                                                     'patch': True,
                                                     'delete': True,
                                                     'version': False},
                                            'spaces': {'url': reverse('spaces-list', request=request),
                                                       'post': True,
                                                       'patch': True,
                                                       'delete': True,
                                                       'version': False},
                                            'sod': {'url': reverse('sod-list', request=request),
                                                    'post': True,
                                                    'patch': True,
                                                    'delete': True,
                                                    'version': True},
                                            'lists': {'url': reverse('lists-list', request=request),
                                                      'post': True,
                                                      'patch': True,
                                                      'delete': True,
                                                      'version': True},
                                            'settings': {'url': reverse('settings-list', request=request),
                                                         'post': False,
                                                         'patch': True,
                                                         'delete': False,
                                                         'version': False}}},
            'logs': {'root': '/logs/',
                     'subjects': {'central': {'url': reverse('central-log-list', request=request)},
                                  'access': {'url': reverse('access-log-list', request=request)},
                                  'roles': {'url': reverse('roles-log-list', request=request)},
                                  'ldap': {'url': reverse('ldap-log-list', request=request)},
                                  'email': {'url': reverse('email-log-list', request=request)},
                                  'users': {'url': reverse('users-log-list', request=request)},
                                  'tags': {'url': reverse('tags-log-list', request=request)},
                                  'spaces': {'url': reverse('spaces-log-list', request=request)},
                                  'sod': {'url': reverse('sod-log-list', request=request)},
                                  'settings': {'url': reverse('settings-log-list', request=request)},
                                  'lists': {'url': reverse('lists-log-list', request=request)}}}}

    return Response(root)


#########
# LOGIN #
#########

@api_view(['POST'])
@csrf_exempt
def login_view(request):
    # FO-137: adapted validation properly and raise serializer validation error (including 400 response)
    if not hasattr(request, 'data'):
        raise serializers.ValidationError('Fields "{}" and "password" are required.'.format(Users.USERNAME_FIELD))
    if Users.USERNAME_FIELD in request.data and 'password' in request.data:
        # FO-137: adapted validation properly and raise serializer validation error (including 400 response)
        if not isinstance(request.data['username'], str) or not isinstance(request.data['password'], str):
            raise serializers.ValidationError('Fields "{}" and "password" must be strings.'
                                              .format(Users.USERNAME_FIELD))
        # authenticate user
        user = authenticate(request=request, username=request.data['username'], password=request.data['password'])
    else:
        # FO-137: raise serializer validation error (including 400 response)
        raise serializers.ValidationError('Fields "{}" and "password" are required.'.format(Users.USERNAME_FIELD))
    if user:
        login(request, user)
        request.session['last_touch'] = timezone.now()
        # pass authenticated user roles to casl method, split to parse
        data = dict()
        # get initial password fag of user
        data['initial_password'] = user.initial_password
        casl = Roles.objects.casl(user.roles.split(','))
        data['casl'] = casl
        return Response(data=data, status=http_status.HTTP_200_OK)
    else:
        return Response(status=http_status.HTTP_400_BAD_REQUEST)


####################
# USER_PERMISSIONS #
####################

@api_view(['GET'])
@auth_required()
@auto_logout()
def user_permissions_view(request):
    data = Roles.objects.permissions(request.user.roles.split(','))
    return Response(data=data, status=http_status.HTTP_200_OK)


###################
# PASSWORD_CHANGE #
###################

@api_view(['PATCH'])
@auth_required()
@perm_required('{}.13'.format(Vault.MODEL_ID))
@auto_logout()
@csrf_protect
def change_password_view(request, username):
    if not hasattr(request, 'data'):
        raise serializers.ValidationError('Fields "password_new" and "password_new_verification" are required.')
    try:
        vault = Vault.objects.get(username=username)
    except Vault.DoesNotExist:
        return Response(status=http_status.HTTP_404_NOT_FOUND)
    except ValidationError:
        return Response(status=http_status.HTTP_400_BAD_REQUEST)

    validate_password_input(request.data, instance=vault)

    create_update_vault(data=request.data, instance=vault, action=settings.DEFAULT_LOG_PASSWORD,
                        user=request.user.username)

    # inform user about successful password change
    user = Users.objects.get_valid_by_key(vault.username)
    email_data = {'fullname': user.get_full_name()}
    html_message = render_email_from_template(template_file_name='email_password_changed.html', data=email_data)
    send_email(subject='OpenGxP Password Changed', html_message=html_message, email=user.email)

    return Response(status=http_status.HTTP_200_OK)


########################
# USER_CHANGE_PASSWORD #
########################

@api_view(['PATCH'])
@auth_required(initial_password_check=False)
@auto_logout()
@csrf_protect
def user_change_password_view(request):
    if not hasattr(request, 'data'):
        raise serializers.ValidationError('Fields "password", "password_new" and "password_new_verification" '
                                          'are required.')
    if 'password' not in request.data:
        raise serializers.ValidationError({'password': ['This filed is required.']})

    try:
        vault = Vault.objects.get(username=request.user.username)
    except Vault.DoesNotExist:
        return Response(status=http_status.HTTP_404_NOT_FOUND)
    except ValidationError:
        return Response(status=http_status.HTTP_400_BAD_REQUEST)

    # check if provided password is correct
    authenticate(request=request, username=request.user.username, password=request.data['password'],
                 self_password_change=True)

    validate_password_input(request.data, instance=vault)

    create_update_vault(data=request.data, instance=vault, action=settings.DEFAULT_LOG_PASSWORD,
                        user=request.user.username, self_pw=True)

    # inform user about successful password change
    user = Users.objects.get_valid_by_key(vault.username)
    email_data = {'fullname': user.get_full_name()}
    html_message = render_email_from_template(template_file_name='email_password_changed.html', data=email_data)
    send_email(subject='OpenGxP Password Changed', html_message=html_message, email=user.email)

    return Response(status=http_status.HTTP_200_OK)


#########################
# USER_CHANGE_QUESTIONS #
#########################

@api_view(['PATCH'])
@auth_required()
@auto_logout()
@csrf_protect
def user_change_questions_view(request):
    if not hasattr(request, 'data'):
        raise serializers.ValidationError('Data is required.')

    error_dict = dict()
    field_error = ['This filed is required.']

    # password is always required if security questions are changed
    if 'password' not in request.data:
        error_dict['password'] = field_error

    # all questions / answers must be provided
    question_answer_fields = Vault.question_answers_fields()
    for question, answer in question_answer_fields.items():
        if question not in request.data:
            error_dict[question] = field_error
        if answer not in request.data:
            error_dict[answer] = field_error

    if error_dict:
        raise serializers.ValidationError(error_dict)

    # questions and answers must be unique
    items = list()
    for question, answer in question_answer_fields.items():
        items.append(request.data[question])
        items.append(request.data[answer])

    if not unique_items(items):
        raise serializers.ValidationError('Questions and answers must be unique.')

    try:
        vault = Vault.objects.get(username=request.user.username)
    except Vault.DoesNotExist:
        return Response(status=http_status.HTTP_404_NOT_FOUND)
    except ValidationError:
        return Response(status=http_status.HTTP_400_BAD_REQUEST)

    # check if provided password is correct
    authenticate(request=request, username=request.user.username, password=request.data['password'],
                 self_password_change=True)

    data = dict()
    for question, answer in question_answer_fields.items():
        data[question] = request.data[question]
        # save answers like passwords
        data[answer] = make_password(request.data[answer])

    create_update_vault(data=data, instance=vault, action=settings.DEFAULT_LOG_QUESTIONS, user=request.user.username)

    return Response(status=http_status.HTTP_200_OK)


################################
# PASSWORD_RESET_EMAIL_REQUEST #
################################

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


########################
# PASSWORD_RESET_EMAIL #
########################

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


########
# CSRF #
########

@api_view(['GET'])
@auth_required(initial_password_check=False)
def get_csrf_token(request):
    token = {settings.CSRF_COOKIE_NAME: get_token(request)}
    return Response(data=token, status=http_status.HTTP_200_OK)


##########
# LOGOUT #
##########

@api_view(['GET'])
@auth_required()
def logout_view(request):
    data = {
        'user': request.user.username,
        'timestamp': timezone.now(),
        'mode': 'manual',
        'method': Settings.objects.core_devalue,
        'action': settings.DEFAULT_LOG_LOGOUT,
        'attempt': Settings.objects.core_devalue,
        'active': Settings.objects.core_devalue
    }
    logout(request)
    if request.user.is_anonymous:
        write_access_log(data)
        return Response(status=http_status.HTTP_200_OK)
    else:
        return Response(status=http_status.HTTP_400_BAD_REQUEST)


##########
# STATUS #
##########

# GET list
@api_view(['GET'])
@auth_required()
@auto_logout()
@perm_required('01.01')
def status_list(request):
    """
    List all status.
    """
    stat = Status.objects.all()
    serializer = StatusReadWriteSerializer(stat, many=True)
    return Response(serializer.data)


#############
# STATUSLOG #
#############

# GET list
@api_view(['GET'])
@auth_required()
@auto_logout()
@perm_required('07.01')
def status_log_list(request):
    """
    List all status log records.
    """
    logs = StatusLog.objects.all()
    serializer = StatusLogReadSerializer(logs, many=True)
    return Response(serializer.data)


###############
# PERMISSIONS #
###############

# GET list
@api_view(['GET'])
@auth_required()
@auto_logout()
@perm_required('{}.01'.format(Roles.MODEL_ID))
def permissions_list(request):
    """
    List all permissions.
    """
    perm = Permissions.objects.all()
    serializer = PermissionsReadWriteSerializer(perm, many=True)
    return Response(serializer.data)


##################
# PERMISSIONSLOG #
##################

# GET list
@api_view(['GET'])
@auth_required()
@auto_logout()
@perm_required('{}.01'.format(RolesLog.MODEL_ID))
def permissions_log_list(request):
    """
    List all permissions log records.
    """
    logs = PermissionsLog.objects.all()
    serializer = PermissionsLogReadSerializer(logs, many=True)
    return Response(serializer.data)


###############
# SETTINGSLOG #
###############

# GET list
@api_view(['GET'])
@auth_required()
@auto_logout()
@perm_required('{}.01'.format(SettingsLog.MODEL_ID))
def settings_log_list(request):
    """
    List all settings log records.
    """
    logs = SettingsLog.objects.all()
    serializer = SettingsLogReadSerializer(logs, many=True)
    return Response(serializer.data)


############
# SETTINGS #
############

# GET list
@api_view(['GET'])
@auth_required()
@auto_logout()
@ensure_csrf_cookie
@perm_required('{}.01'.format(Settings.MODEL_ID))
def settings_list(request):
    """
    List all settings records.
    """
    query = Settings.objects.all()
    serializer = SettingsReadWriteSerializer(query, many=True)
    return Response(serializer.data)


# GET detail
@api_view(['GET', 'PATCH'])
@auth_required()
@auto_logout()
def settings_detail(request, key):
    @perm_required('{}.03'.format(Settings.MODEL_ID))
    @csrf_protect
    def patch(_request):
        _serializer = SettingsReadWriteSerializer(query, data=_request.data, context={'method': 'PATCH',
                                                                                      'function': '',
                                                                                      'user': request.user.username})
        if _serializer.is_valid():
            _serializer.save()
            return Response(_serializer.data)
        return Response(_serializer.errors, status=http_status.HTTP_400_BAD_REQUEST)

    @perm_required('{}.01'.format(Settings.MODEL_ID))
    @ensure_csrf_cookie
    def get(_request):
        serializer = SettingsReadWriteSerializer(query)
        return Response(serializer.data)

    try:
        query = Settings.objects.get(key=key)
    except Settings.DoesNotExist:
        return Response(status=http_status.HTTP_404_NOT_FOUND)
    except ValidationError:
        return Response(status=http_status.HTTP_400_BAD_REQUEST)

    if request.method == 'GET':
        return get(request)

    elif request.method == 'PATCH':
        return patch(request)


###########
# TAGSLOG #
###########

# GET list
@api_view(['GET'])
@auth_required()
@auto_logout()
@perm_required('{}.01'.format(TagsLog.MODEL_ID))
def tags_log_list(request):
    logs = TagsLog.objects.all()
    serializer = TagsLogReadSerializer(logs, many=True)
    return Response(serializer.data)


########
# TAGS #
########

# GET list
@api_view(['GET', 'POST'])
@auth_required()
@auto_logout()
def tags_list(request):
    @perm_required('{}.02'.format(Tags.MODEL_ID))
    @csrf_protect
    def post(_request):
        _serializer = TagsReadWriteSerializer(data=_request.data, context={'method': 'POST',
                                                                           'function': 'new',
                                                                           'user': request.user.username})

        if _serializer.is_valid():
            _serializer.save()
            return Response(_serializer.data, status=http_status.HTTP_201_CREATED)
        return Response(_serializer.errors, status=http_status.HTTP_400_BAD_REQUEST)

    @perm_required('{}.01'.format(Tags.MODEL_ID))
    @ensure_csrf_cookie
    def get(_request):
        query = Tags.objects.all()
        serializer = TagsReadWriteSerializer(query, many=True)
        return Response(serializer.data)

    if request.method == 'GET':
        return get(request)
    if request.method == 'POST':
        return post(request)


# GET detail
@api_view(['GET', 'PATCH', 'DELETE'])
@auth_required()
@auto_logout()
def tags_detail(request, tag):
    @perm_required('{}.03'.format(Tags.MODEL_ID))
    @csrf_protect
    def patch(_request):
        _serializer = TagsReadWriteSerializer(query, data=_request.data, context={'method': 'PATCH',
                                                                                  'function': '',
                                                                                  'user': request.user.username})
        if _serializer.is_valid():
            _serializer.save()
            return Response(_serializer.data)
        return Response(_serializer.errors, status=http_status.HTTP_400_BAD_REQUEST)

    @perm_required('{}.04'.format(Tags.MODEL_ID))
    @csrf_protect
    def delete(_request):
        _serializer = TagsDeleteSerializer(query, data={}, context={'method': 'DELETE',
                                                                    'function': '',
                                                                    'user': request.user.username})
        if _serializer.is_valid():
            _serializer.delete()
            return Response(status=http_status.HTTP_204_NO_CONTENT)
        return Response(_serializer.errors, status=http_status.HTTP_400_BAD_REQUEST)

    @perm_required('{}.01'.format(Tags.MODEL_ID))
    @ensure_csrf_cookie
    def get(_request):
        serializer = TagsReadWriteSerializer(query)
        return Response(serializer.data)

    try:
        query = Tags.objects.get(tag=tag)
    except Tags.DoesNotExist:
        return Response(status=http_status.HTTP_404_NOT_FOUND)
    except ValidationError:
        return Response(status=http_status.HTTP_400_BAD_REQUEST)

    if request.method == 'GET':
        return get(request)

    elif request.method == 'PATCH':
        return patch(request)

    elif request.method == 'DELETE':
        return delete(request)


###########
# LDAPLOG #
###########

# GET list
@api_view(['GET'])
@auth_required()
@auto_logout()
@perm_required('{}.01'.format(LDAPLog.MODEL_ID))
def ldap_log_list(request):
    """
    List all ldap log records.
    """
    logs = LDAPLog.objects.all()
    serializer = LDAPLogReadSerializer(logs, many=True)
    return Response(serializer.data)


########
# LDAP #
########

# GET list
@api_view(['GET', 'POST'])
@auth_required()
@auto_logout()
def ldap_list(request):
    @perm_required('{}.02'.format(LDAP.MODEL_ID))
    @csrf_protect
    def post(_request):
        _serializer = LDAPReadWriteSerializer(data=_request.data, context={'method': 'POST',
                                                                           'function': 'new',
                                                                           'user': request.user.username})

        if _serializer.is_valid():
            _serializer.save()
            return Response(_serializer.data, status=http_status.HTTP_201_CREATED)
        return Response(_serializer.errors, status=http_status.HTTP_400_BAD_REQUEST)

    @perm_required('{}.01'.format(LDAP.MODEL_ID))
    @ensure_csrf_cookie
    def get(_request):
        query = LDAP.objects.all()
        serializer = LDAPReadWriteSerializer(query, many=True)
        return Response(serializer.data)

    if request.method == 'GET':
        return get(request)
    if request.method == 'POST':
        return post(request)


# GET detail
@api_view(['GET', 'PATCH', 'DELETE'])
@auth_required()
@auto_logout()
def ldap_detail(request, host):
    @perm_required('{}.03'.format(LDAP.MODEL_ID))
    @csrf_protect
    def patch(_request):
        _serializer = LDAPReadWriteSerializer(query, data=_request.data, context={'method': 'PATCH',
                                                                                  'function': '',
                                                                                  'user': request.user.username})
        if _serializer.is_valid():
            _serializer.save()
            return Response(_serializer.data)
        return Response(_serializer.errors, status=http_status.HTTP_400_BAD_REQUEST)

    @perm_required('{}.04'.format(LDAP.MODEL_ID))
    @csrf_protect
    def delete(_request):
        _serializer = LDAPDeleteSerializer(query, data={}, context={'method': 'DELETE',
                                                                    'function': '',
                                                                    'user': request.user.username})
        if _serializer.is_valid():
            _serializer.delete()
            return Response(status=http_status.HTTP_204_NO_CONTENT)
        return Response(_serializer.errors, status=http_status.HTTP_400_BAD_REQUEST)

    @perm_required('{}.01'.format(LDAP.MODEL_ID))
    @ensure_csrf_cookie
    def get(_request):
        serializer = LDAPReadWriteSerializer(query)
        return Response(serializer.data)

    try:
        query = LDAP.objects.get(host=host)
    except LDAP.DoesNotExist:
        return Response(status=http_status.HTTP_404_NOT_FOUND)
    except ValidationError:
        return Response(status=http_status.HTTP_400_BAD_REQUEST)

    if request.method == 'GET':
        return get(request)

    elif request.method == 'PATCH':
        return patch(request)

    elif request.method == 'DELETE':
        return delete(request)


############
# EMAILLOG #
############

# GET list
@api_view(['GET'])
@auth_required()
@auto_logout()
@perm_required('{}.01'.format(EmailLog.MODEL_ID))
def email_log_list(request):
    """
    List all email log records.
    """
    logs = EmailLog.objects.all()
    serializer = EmailLogReadSerializer(logs, many=True)
    return Response(serializer.data)


#########
# EMAIL #
#########

# GET list
@api_view(['GET', 'POST'])
@auth_required()
@auto_logout()
def email_list(request):
    @perm_required('{}.02'.format(Email.MODEL_ID))
    @csrf_protect
    def post(_request):
        _serializer = EmailReadWriteSerializer(data=_request.data, context={'method': 'POST',
                                                                            'function': 'new',
                                                                            'user': request.user.username})

        if _serializer.is_valid():
            _serializer.save()
            return Response(_serializer.data, status=http_status.HTTP_201_CREATED)
        return Response(_serializer.errors, status=http_status.HTTP_400_BAD_REQUEST)

    @perm_required('{}.01'.format(Email.MODEL_ID))
    @ensure_csrf_cookie
    def get(_request):
        query = Email.objects.all()
        serializer = EmailReadWriteSerializer(query, many=True)
        return Response(serializer.data)

    if request.method == 'GET':
        return get(request)
    if request.method == 'POST':
        return post(request)


# GET detail
@api_view(['GET', 'PATCH', 'DELETE'])
@auth_required()
@auto_logout()
def email_detail(request, host):
    @perm_required('{}.03'.format(Email.MODEL_ID))
    @csrf_protect
    def patch(_request):
        _serializer = EmailReadWriteSerializer(query, data=_request.data, context={'method': 'PATCH',
                                                                                   'function': '',
                                                                                   'user': request.user.username})
        if _serializer.is_valid():
            _serializer.save()
            return Response(_serializer.data)
        return Response(_serializer.errors, status=http_status.HTTP_400_BAD_REQUEST)

    @perm_required('{}.04'.format(Email.MODEL_ID))
    @csrf_protect
    def delete(_request):
        _serializer = EmailDeleteSerializer(query, data={}, context={'method': 'DELETE',
                                                                     'function': '',
                                                                     'user': request.user.username})
        if _serializer.is_valid():
            _serializer.delete()
            return Response(status=http_status.HTTP_204_NO_CONTENT)
        return Response(_serializer.errors, status=http_status.HTTP_400_BAD_REQUEST)

    @perm_required('{}.01'.format(Email.MODEL_ID))
    @ensure_csrf_cookie
    def get(_request):
        serializer = EmailReadWriteSerializer(query)
        return Response(serializer.data)

    try:
        query = Email.objects.get(host=host)
    except Email.DoesNotExist:
        return Response(status=http_status.HTTP_404_NOT_FOUND)
    except ValidationError:
        return Response(status=http_status.HTTP_400_BAD_REQUEST)

    if request.method == 'GET':
        return get(request)

    elif request.method == 'PATCH':
        return patch(request)

    elif request.method == 'DELETE':
        return delete(request)


##############
# CENTRALLOG #
##############

# GET list
@api_view(['GET'])
@auth_required()
@auto_logout()
@perm_required('06.01')
def central_log_list(request):
    logs = CentralLog.objects.all()
    serializer = CentralLogReadWriteSerializer(logs, many=True)
    return Response(serializer.data)


#############
# ACCESSLOG #
#############

# GET list
@api_view(['GET'])
@auth_required()
@auto_logout()
@perm_required('05.01')
def access_log_list(request):
    logs = AccessLog.objects.all()
    serializer = AccessLogReadWriteSerializer(logs, many=True)
    return Response(serializer.data)


###############
# AUDIT_TRAIL #
###############

# GET list
@api_view(['GET'])
@auth_required()
@auto_logout()
def audit_trail_list(request, dialog, lifecycle_id):
    # lower all inputs for dialog
    dialog = dialog.lower()
    # determine the model instance from string parameter
    try:
        model = get_model_by_string(dialog).objects.LOG_TABLE
    except ValidationError:
        return Response(status=http_status.HTTP_400_BAD_REQUEST)

    @perm_required('{}.01'.format(model.MODEL_ID))
    def get(_request):
        # check if at least one record exists
        try:
            record = model.objects.filter(lifecycle_id=lifecycle_id).get()
            serializer = AUDIT_TRAIL_SERIALIZERS[dialog](record)
        # no record exists for that lifecycle_id
        except model.DoesNotExist:
            return Response(status=http_status.HTTP_404_NOT_FOUND)
        # not a valid lifecycle_id
        except ValidationError:
            return Response(status=http_status.HTTP_400_BAD_REQUEST)
        # lifecycle_id ok and multiple records, no error
        except model.MultipleObjectsReturned:
            records = model.objects.filter(lifecycle_id=lifecycle_id).all()
            serializer = AUDIT_TRAIL_SERIALIZERS[dialog](records, many=True)
        return Response(serializer.data)

    if request.method == 'GET':
        return get(request)


#################
# USERSPASSWORD #
#################

# GET list
@api_view(['GET'])
@auth_required()
@auto_logout()
@ensure_csrf_cookie
@perm_required('{}.01'.format(Vault.MODEL_ID))
def users_password_list(request):
    users = Vault.objects.all()
    serializer = UsersPassword(users, many=True)
    return Response(serializer.data)


################
# USER_PROFILE #
################

# GET list
@api_view(['GET'])
@auth_required()
@auto_logout()
@ensure_csrf_cookie
def user_profile_list(request):
    try:
        user = Vault.objects.filter(username=request.user.username).get()
    except Vault.DoesNotExist:
        raise serializers.ValidationError('Profile for ldap managed users does not exist.')
    serializer = UserProfile(user)
    return Response(serializer.data)


########
# META #
########

@api_view(['GET'])
@auth_required()
def meta_list(request, dialog):
    # lower all inputs for dialog
    dialog = dialog.lower()
    # filter out status because no public dialog
    if dialog in ['status', 'tokens']:
        return Response(status=http_status.HTTP_400_BAD_REQUEST)
    # determine the model instance from string parameter

    if dialog == 'profile':
        ldap = request.user.ldap
        data = {'get': {},
                'ldap': ldap}
        if not ldap:
            # add calculated field "valid"
            data['get']['valid'] = {'verbose_name': 'Valid',
                                    'data_type': 'CharField',
                                    'render': False,
                                    'format': None}
            # add calculated field "unique"
            data['get']['unique'] = {'verbose_name': 'Unique',
                                     'data_type': 'CharField',
                                     'render': False,
                                     'format': None}

            # add questions fields
            data['get']['question_one'] = {'verbose_name': 'Question one',
                                           'data_type': 'CharField',
                                           'render': True,
                                           'format': None}
            data['get']['question_two'] = {'verbose_name': 'Question two',
                                           'data_type': 'CharField',
                                           'render': True,
                                           'format': None}
            data['get']['question_three'] = {'verbose_name': 'Question three',
                                             'data_type': 'CharField',
                                             'render': True,
                                             'format': None}
        return Response(data=data, status=http_status.HTTP_200_OK)

    try:
        model = get_model_by_string(dialog)
    except ValidationError:
        return Response(status=http_status.HTTP_400_BAD_REQUEST)

    def get(_request):
        data = {'get': dict(),
                'post': dict()}
        # add get information
        exclude = model.objects.GET_BASE_EXCLUDE + model.objects.GET_MODEL_EXCLUDE
        fields = [i for i in model._meta.get_fields() if i.name not in exclude]
        not_render = model.objects.GET_BASE_NOT_RENDER + model.objects.GET_MODEL_NOT_RENDER
        # add calculated field "valid"
        data['get']['valid'] = {'verbose_name': 'Valid',
                                'data_type': 'CharField',
                                'render': False,
                                'format': None}
        # add calculated field "unique"
        data['get']['unique'] = {'verbose_name': 'Unique',
                                 'data_type': 'CharField',
                                 'render': False,
                                 'format': None}
        for f in fields:
            if f.name in not_render:
                render = False
            else:
                render = True
            # add format for timestamp
            if f.name in ['timtestamp', 'valid_from', 'valid_to']:
                _format = Settings.objects.core_timestamp_format
            else:
                _format = None
            data['get'][f.name] = {'verbose_name': f.verbose_name,
                                   'data_type': f.get_internal_type(),
                                   'render': render,
                                   'format': _format}

        # add post information
        if dialog in ['users', 'roles', 'ldap', 'settings', 'sod', 'email', 'passwords', 'tags', 'spaces', 'lists']:
            exclude = model.objects.POST_BASE_EXCLUDE + model.objects.POST_MODEL_EXCLUDE
            fields = [i for i in model._meta.get_fields() if i.name not in exclude]
            for f in fields:
                data['post'][f.name] = {'verbose_name': f.verbose_name,
                                        'help_text': f.help_text,
                                        'max_length': f.max_length,
                                        'data_type': f.get_internal_type(),
                                        'required': not f.blank,
                                        'unique': f.unique,
                                        'lookup': None,
                                        'editable': True}
                if f.name == 'password':
                    data['post'][f.name]['data_type'] = 'PasswordField'

                # create lookup data
                if model.LOOKUP:
                    if f.name in model.LOOKUP:
                        data_model = model.LOOKUP[f.name]['model']
                        if not isinstance(data_model, ModelBase):
                            data['post'][f.name]['lookup'] = {
                                'data': data_model,
                                'multi': model.LOOKUP[f.name]['multi'],
                                'method': model.LOOKUP[f.name]['method']}
                        else:
                            data['post'][f.name]['lookup'] = {
                                'data': data_model.objects.get_by_natural_key_productive_list(
                                    model.LOOKUP[f.name]['key']),
                                'multi': model.LOOKUP[f.name]['multi'],
                                'method': model.LOOKUP[f.name]['method']}

                # settings non-editable field for better visualisation
                if dialog == 'settings' and f.name == 'key':
                    data['post'][f.name]['editable'] = False
                    data['post'][f.name]['required'] = False
                if dialog == 'settings' and f.name == 'default':
                    data['post'][f.name]['editable'] = False
                    data['post'][f.name]['required'] = False

            if dialog == 'users':
                # add calculated field "password_verification"
                data['post']['password_verification'] = {'verbose_name': 'Password verification',
                                                         'help_text': '{}'.format(password_validators_help_texts()),
                                                         'max_length': CHAR_MAX,
                                                         'data_type': 'PasswordField',
                                                         'required': True,
                                                         'unique': False,
                                                         'lookup': None,
                                                         'editable': True}
            if dialog == 'passwords':
                # add calculated fields for manual password reset
                data['post']['password_new'] = {'verbose_name': 'New password',
                                                'help_text': '{}'.format(password_validators_help_texts()),
                                                'max_length': CHAR_MAX,
                                                'data_type': 'PasswordField',
                                                'required': True,
                                                'unique': False,
                                                'lookup': None,
                                                'editable': True}
                data['post']['password_new_verification'] = {'verbose_name': 'New password verification',
                                                             'help_text': '{}'.format(password_validators_help_texts()),
                                                             'max_length': CHAR_MAX,
                                                             'data_type': 'PasswordField',
                                                             'required': True,
                                                             'unique': False,
                                                             'lookup': None,
                                                             'editable': True}
        return Response(data=data, status=http_status.HTTP_200_OK)

    if request.method == 'GET':
        return get(request)


#########
# ROLES #
#########

# GET list
@api_view(['GET', 'POST'])
@auth_required()
@auto_logout()
def roles_list(request):
    """
    List all roles.
    """

    @perm_required('03.02')
    @csrf_protect
    def post(_request):
        # add version for new objects because of combined unique constraint
        _request.data['version'] = 1
        _serializer = RolesWriteSerializer(data=_request.data, context={'method': 'POST',
                                                                        'function': 'new',
                                                                        'user': request.user.username})
        if _serializer.is_valid():
            _serializer.save()
            return Response(_serializer.data, status=http_status.HTTP_201_CREATED)
        return Response(_serializer.errors, status=http_status.HTTP_400_BAD_REQUEST)

    @perm_required('03.01')
    @ensure_csrf_cookie
    def get(_request):
        roles = Roles.objects.all()
        serializer = RolesReadSerializer(roles, many=True)
        return Response(serializer.data)

    if request.method == 'GET':
        return get(request)
    if request.method == 'POST':
        return post(request)


# GET detail
@api_view(['GET', 'PATCH', 'POST', 'DELETE'])
@auth_required()
@auto_logout()
def roles_detail(request, lifecycle_id, version):
    """
    Retrieve roles.
    """

    @perm_required('03.03')
    @csrf_protect
    def patch(_request):
        _serializer = RolesWriteSerializer(role, data=_request.data, context={'method': 'PATCH',
                                                                              'function': '',
                                                                              'user': request.user.username})
        if _serializer.is_valid():
            _serializer.save()
            return Response(_serializer.data)
        return Response(_serializer.errors, status=http_status.HTTP_400_BAD_REQUEST)

    @csrf_protect
    def post_base(_request):
        _serializer = RolesNewVersionSerializer(role, data=_request.data, context={'method': 'POST',
                                                                                   'function': 'new_version',
                                                                                   'user': request.user.username})
        if _serializer.is_valid():
            _serializer.create(validated_data=_serializer.validated_data)
            return Response(_serializer.data, status=http_status.HTTP_201_CREATED)
        return Response(_serializer.errors, status=http_status.HTTP_400_BAD_REQUEST)

    @perm_required('03.11')
    def post(_request):
        return post_base(_request)

    @perm_required('03.12')
    def post_archived(_request):
        return post_base(_request)

    @perm_required('03.04')
    @csrf_protect
    def delete(_request):
        _serializer = RolesDeleteStatusSerializer(role, data={}, context={'method': 'DELETE',
                                                                          'function': '',
                                                                          'user': request.user.username})
        if _serializer.is_valid():
            _serializer.delete()
            return Response(status=http_status.HTTP_204_NO_CONTENT)
        return Response(_serializer.errors, status=http_status.HTTP_400_BAD_REQUEST)

    @perm_required('03.01')
    @ensure_csrf_cookie
    def get(_request):
        serializer = RolesReadSerializer(role)
        return Response(serializer.data)

    try:
        role = Roles.objects.get(lifecycle_id=lifecycle_id, version=version)
    except Roles.DoesNotExist:
        return Response(status=http_status.HTTP_404_NOT_FOUND)
    except ValidationError:
        return Response(status=http_status.HTTP_400_BAD_REQUEST)

    if request.method == 'GET':
        return get(request)

    elif request.method == 'PATCH':
        return patch(request)

    elif request.method == 'POST':
        if role.status.id == Status.objects.archived:
            return post_archived(request)
        else:
            return post(request)

    elif request.method == 'DELETE':
        return delete(request)


@api_view(['PATCH'])
@auth_required()
@auto_logout()
def roles_status(request, lifecycle_id, version, status):
    @csrf_protect
    def patch_base(_request):
        _serializer = RolesDeleteStatusSerializer(role, data={}, context={'method': 'PATCH',
                                                                          'function': 'status_change',
                                                                          'status': status,
                                                                          'user': request.user.username})
        if _serializer.is_valid():
            _serializer.save()
            return Response(_serializer.data)
        return Response(_serializer.errors, status=http_status.HTTP_400_BAD_REQUEST)

    @perm_required('03.05')
    def patch_circulation(_request):
        return patch_base(_request)

    @perm_required('03.06')
    def patch_draft(_request):
        return patch_base(_request)

    @perm_required('03.07')
    def patch_productive(_request):
        return patch_base(_request)

    @perm_required('03.08')
    def patch_blocked(_request):
        return patch_base(_request)

    @perm_required('03.09')
    def patch_archived(_request):
        return patch_base(_request)

    @perm_required('03.10')
    def patch_inactive(_request):
        return patch_base(_request)

    try:
        role = Roles.objects.get(lifecycle_id=lifecycle_id, version=version)
    except Roles.DoesNotExist:
        return Response(status=http_status.HTTP_404_NOT_FOUND)
    except ValidationError:
        return Response(status=http_status.HTTP_400_BAD_REQUEST)

    if request.method == 'PATCH':
        if status == 'circulation':
            return patch_circulation(request)
        if status == 'draft':
            return patch_draft(request)
        if status == 'productive':
            return patch_productive(request)
        if status == 'blocked':
            return patch_blocked(request)
        if status == 'archived':
            return patch_archived(request)
        if status == 'inactive':
            return patch_inactive(request)
        return patch_base(request)


############
# ROLESLOG #
############

# GET list
@api_view(['GET'])
@auth_required()
@auto_logout()
@perm_required('09.01')
def roles_log_list(request):
    """
    List all roles log records.
    """
    logs = RolesLog.objects.all()
    serializer = RolesLogReadSerializer(logs, many=True)
    return Response(serializer.data)


#########
# USERS #
#########

# GET list
@api_view(['GET', 'POST'])
@auth_required()
@auto_logout()
def users_list(request):
    @perm_required('04.02')
    @csrf_protect
    def post(_request):
        # add version for new objects because of combined unique constraint
        _request.data['version'] = 1
        _serializer = UsersWriteSerializer(data=_request.data, context={'method': 'POST',
                                                                        'function': 'new',
                                                                        'user': request.user.username})
        if _serializer.is_valid():
            _serializer.save()
            return Response(_serializer.data, status=http_status.HTTP_201_CREATED)
        return Response(_serializer.errors, status=http_status.HTTP_400_BAD_REQUEST)

    @perm_required('04.01')
    @ensure_csrf_cookie
    def get(_request):
        users = Users.objects.all()
        serializer = UsersReadSerializer(users, many=True)
        return Response(serializer.data)

    if request.method == 'GET':
        return get(request)
    if request.method == 'POST':
        return post(request)


# GET detail
@api_view(['GET', 'PATCH', 'POST', 'DELETE'])
@auth_required()
@auto_logout()
def users_detail(request, lifecycle_id, version):
    @perm_required('04.03')
    @csrf_protect
    def patch(_request):
        _serializer = UsersWriteSerializer(user, data=_request.data, context={'method': 'PATCH',
                                                                              'function': '',
                                                                              'user': request.user.username})
        if _serializer.is_valid():
            _serializer.save()
            return Response(_serializer.data)
        return Response(_serializer.errors, status=http_status.HTTP_400_BAD_REQUEST)

    @perm_required('04.01')
    @ensure_csrf_cookie
    def get(_request):
        serializer = UsersReadSerializer(user)
        return Response(serializer.data)

    @csrf_protect
    def post_base(_request):
        _serializer = UsersNewVersionSerializer(user, data=_request.data, context={'method': 'POST',
                                                                                   'function': 'new_version',
                                                                                   'user': request.user.username})
        if _serializer.is_valid():
            _serializer.create(validated_data=_serializer.validated_data)
            return Response(_serializer.data, status=http_status.HTTP_201_CREATED)
        return Response(_serializer.errors, status=http_status.HTTP_400_BAD_REQUEST)

    @perm_required('04.11')
    def post(_request):
        return post_base(_request)

    @perm_required('04.12')
    def post_archived(_request):
        return post_base(_request)

    @perm_required('04.04')
    @csrf_protect
    def delete(_request):
        _serializer = UsersDeleteStatusSerializer(user, data={}, context={'method': 'DELETE',
                                                                          'function': '',
                                                                          'user': request.user.username})
        if _serializer.is_valid():
            _serializer.delete()
            return Response(status=http_status.HTTP_204_NO_CONTENT)
        return Response(_serializer.errors, status=http_status.HTTP_400_BAD_REQUEST)

    try:
        user = Users.objects.get(lifecycle_id=lifecycle_id, version=version)
    except Users.DoesNotExist:
        return Response(status=http_status.HTTP_404_NOT_FOUND)
    except ValidationError:
        return Response(status=http_status.HTTP_400_BAD_REQUEST)

    if request.method == 'GET':
        return get(request)

    elif request.method == 'PATCH':
        return patch(request)

    elif request.method == 'POST':
        if user.status.id == Status.objects.archived:
            return post_archived(request)
        else:
            return post(request)

    elif request.method == 'DELETE':
        return delete(request)


@api_view(['PATCH'])
@auth_required()
@auto_logout()
def users_status(request, lifecycle_id, version, status):
    @csrf_protect
    def patch_base(_request):
        _serializer = UsersDeleteStatusSerializer(user, data={}, context={'method': 'PATCH',
                                                                          'function': 'status_change',
                                                                          'status': status,
                                                                          'user': request.user.username})
        if _serializer.is_valid():
            _serializer.save()
            return Response(_serializer.data)
        return Response(_serializer.errors, status=http_status.HTTP_400_BAD_REQUEST)

    @perm_required('04.05')
    def patch_circulation(_request):
        return patch_base(_request)

    @perm_required('04.06')
    def patch_draft(_request):
        return patch_base(_request)

    @perm_required('04.07')
    def patch_productive(_request):
        return patch_base(_request)

    @perm_required('04.08')
    def patch_blocked(_request):
        return patch_base(_request)

    @perm_required('04.09')
    def patch_archived(_request):
        return patch_base(_request)

    @perm_required('04.10')
    def patch_inactive(_request):
        return patch_base(_request)

    try:
        user = Users.objects.get(lifecycle_id=lifecycle_id, version=version)
    except Users.DoesNotExist:
        return Response(status=http_status.HTTP_404_NOT_FOUND)
    except ValidationError:
        return Response(status=http_status.HTTP_400_BAD_REQUEST)

    if request.method == 'PATCH':
        if status == 'circulation':
            return patch_circulation(request)
        if status == 'draft':
            return patch_draft(request)
        if status == 'productive':
            return patch_productive(request)
        if status == 'blocked':
            return patch_blocked(request)
        if status == 'archived':
            return patch_archived(request)
        if status == 'inactive':
            return patch_inactive(request)
        return patch_base(request)


############
# USERSLOG #
############

# GET list
@api_view(['GET'])
@auth_required()
@auto_logout()
@perm_required('10.01')
def users_log_list(request):
    """
    List all users log records.
    """
    logs = UsersLog.objects.all()
    serializer = UsersLogReadSerializer(logs, many=True)
    return Response(serializer.data)


#######
# SOD #
#######

# GET list
@api_view(['GET', 'POST'])
@auth_required()
@auto_logout()
def sod_list(request):
    @perm_required('{}.02'.format(SoD.MODEL_ID))
    @csrf_protect
    def post(_request):
        # add version for new objects because of combined unique constraint
        _request.data['version'] = 1
        _serializer = SoDWriteSerializer(data=_request.data, context={'method': 'POST',
                                                                      'function': 'new',
                                                                      'user': request.user.username})
        if _serializer.is_valid():
            _serializer.save()
            return Response(_serializer.data, status=http_status.HTTP_201_CREATED)
        return Response(_serializer.errors, status=http_status.HTTP_400_BAD_REQUEST)

    @perm_required('{}.01'.format(SoD.MODEL_ID))
    @ensure_csrf_cookie
    def get(_request):
        roles = SoD.objects.all()
        serializer = SoDReadSerializer(roles, many=True)
        return Response(serializer.data)

    if request.method == 'GET':
        return get(request)
    if request.method == 'POST':
        return post(request)


# GET detail
@api_view(['GET', 'PATCH', 'POST', 'DELETE'])
@auth_required()
@auto_logout()
def sod_detail(request, lifecycle_id, version):
    @perm_required('{}.03'.format(SoD.MODEL_ID))
    @csrf_protect
    def patch(_request):
        _serializer = SoDWriteSerializer(role, data=_request.data, context={'method': 'PATCH',
                                                                            'function': '',
                                                                            'user': request.user.username})
        if _serializer.is_valid():
            _serializer.save()
            return Response(_serializer.data)
        return Response(_serializer.errors, status=http_status.HTTP_400_BAD_REQUEST)

    @csrf_protect
    def post_base(_request):
        _serializer = SoDDeleteStatusNewVersionSerializer(role, data=_request.data,
                                                          context={'method': 'POST',
                                                                   'function': 'new_version',
                                                                   'user': request.user.username})
        if _serializer.is_valid():
            _serializer.create(validated_data=_serializer.validated_data)
            return Response(_serializer.data, status=http_status.HTTP_201_CREATED)
        return Response(_serializer.errors, status=http_status.HTTP_400_BAD_REQUEST)

    @perm_required('{}.11'.format(SoD.MODEL_ID))
    def post(_request):
        return post_base(_request)

    @perm_required('{}.12'.format(SoD.MODEL_ID))
    def post_archived(_request):
        return post_base(_request)

    @perm_required('{}.04'.format(SoD.MODEL_ID))
    @csrf_protect
    def delete(_request):
        _serializer = SoDDeleteStatusNewVersionSerializer(role, data={}, context={'method': 'DELETE',
                                                                                  'function': '',
                                                                                  'user': request.user.username})
        if _serializer.is_valid():
            _serializer.delete()
            return Response(status=http_status.HTTP_204_NO_CONTENT)
        return Response(_serializer.errors, status=http_status.HTTP_400_BAD_REQUEST)

    @perm_required('{}.01'.format(SoD.MODEL_ID))
    @ensure_csrf_cookie
    def get(_request):
        serializer = SoDReadSerializer(role)
        return Response(serializer.data)

    try:
        role = SoD.objects.get(lifecycle_id=lifecycle_id, version=version)
    except SoD.DoesNotExist:
        return Response(status=http_status.HTTP_404_NOT_FOUND)
    except ValidationError:
        return Response(status=http_status.HTTP_400_BAD_REQUEST)

    if request.method == 'GET':
        return get(request)

    elif request.method == 'PATCH':
        return patch(request)

    elif request.method == 'POST':
        if role.status.id == Status.objects.archived:
            return post_archived(request)
        else:
            return post(request)

    elif request.method == 'DELETE':
        return delete(request)


@api_view(['PATCH'])
@auth_required()
@auto_logout()
def sod_status(request, lifecycle_id, version, status):
    @csrf_protect
    def patch_base(_request):
        _serializer = SoDDeleteStatusNewVersionSerializer(role, data={}, context={'method': 'PATCH',
                                                                                  'function': 'status_change',
                                                                                  'status': status,
                                                                                  'user': request.user.username})
        if _serializer.is_valid():
            _serializer.save()
            return Response(_serializer.data)
        return Response(_serializer.errors, status=http_status.HTTP_400_BAD_REQUEST)

    @perm_required('{}.05'.format(SoD.MODEL_ID))
    def patch_circulation(_request):
        return patch_base(_request)

    @perm_required('{}.06'.format(SoD.MODEL_ID))
    def patch_draft(_request):
        return patch_base(_request)

    @perm_required('{}.07'.format(SoD.MODEL_ID))
    def patch_productive(_request):
        return patch_base(_request)

    @perm_required('{}.08'.format(SoD.MODEL_ID))
    def patch_blocked(_request):
        return patch_base(_request)

    @perm_required('{}.09'.format(SoD.MODEL_ID))
    def patch_archived(_request):
        return patch_base(_request)

    @perm_required('{}.10'.format(SoD.MODEL_ID))
    def patch_inactive(_request):
        return patch_base(_request)

    try:
        role = SoD.objects.get(lifecycle_id=lifecycle_id, version=version)
    except SoD.DoesNotExist:
        return Response(status=http_status.HTTP_404_NOT_FOUND)
    except ValidationError:
        return Response(status=http_status.HTTP_400_BAD_REQUEST)

    if request.method == 'PATCH':
        if status == 'circulation':
            return patch_circulation(request)
        if status == 'draft':
            return patch_draft(request)
        if status == 'productive':
            return patch_productive(request)
        if status == 'blocked':
            return patch_blocked(request)
        if status == 'archived':
            return patch_archived(request)
        if status == 'inactive':
            return patch_inactive(request)
        return patch_base(request)


##########
# SODLOG #
##########

# GET list
@api_view(['GET'])
@auth_required()
@auto_logout()
@perm_required('{}.01'.format(SoDLog.MODEL_ID))
def sod_log_list(request):
    logs = SoDLog.objects.all()
    serializer = SoDLogReadSerializer(logs, many=True)
    return Response(serializer.data)
