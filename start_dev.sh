#!/usr/bin/env bash

rm db.sqlite3
rm urp/migrations/*
rm basics/migrations/*
export DJANGO_SETTINGS_MODULE=forms.settings.dev
python manage.py makemigrations
python manage.py makemigrations basics
python manage.py makemigrations urp
python manage.py migrate
python manage.py generate-key
python manage.py initialize-settings
python manage.py initialize-status
python manage.py collect-permissions
python manage.py create-role --name all
python manage.py create-superuser --username initial --role all --email test@opengxp.org --pwfile
python manage.py create-superuser --username usertwo --role all --email new@opengxp.org --pwfile
python manage.py runserver