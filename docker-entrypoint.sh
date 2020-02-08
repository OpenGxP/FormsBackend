#!/usr/bin/env bash
set -e

# initial role
[[ ! -z "${ROLE}" && "${ROLE}" =~ ^([A-Za-z])+$ ]] || (echo "ROLE must not be empty and match pattern A-Za-z"; exit 1)
# username
[[ ! -z "${USERNAME}" && "${USERNAME}" =~ ^([A-Za-z])+$ ]] || (echo "USERNAME must not be empty and match pattern A-Za-z"; exit 1)
# email
[[ ! -z "${EMAIL}" && "${EMAIL}" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,4}$ ]] || (echo "EMAIL must not be empty and match pattern xxx@xxx.xxx"; exit 1)
# password
[[ ! -z "${PASSWORD}" && $(echo ${#PASSWORD}) -gt 11 && "${PASSWORD}" =~ ^([A-Za-z0-9_§$%&/()!?])+$ ]] || (echo "PASSWORD must not be empty, has at least 12 characters and match pattern A-Za-z0-9_§$%&/()!?"; exit 1)
# setup
export DJANGO_SETTINGS_MODULE=forms.settings.dev
python manage.py makemigrations
python manage.py makemigrations basics
python manage.py makemigrations urp
python manage.py migrate
python manage.py initialize-settings
python manage.py initialize-status
python manage.py collect-permissions
# create initial role
python manage.py create-role --name ${ROLE}
# create initial user
python manage.py create-superuser --username ${USERNAME} --password ${PASSWORD} --role ${ROLE} --email ${EMAIL}
# start server
python manage.py runserver 0.0.0.0:8000
