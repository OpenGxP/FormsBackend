#!/usr/bin/env bash

# rm  db.sqlite3
# rm urp/migrations/*
# rm basics/migrations/*
python manage.py makemigrations
python manage.py makemigrations basics
python manage.py makemigrations urp
python manage.py migrate
export DJANGO_SETTINGS_MODULE=forms.settings
# python manage.py initialize-status
# python manage.py collect-permissions
# python manage.py create-role --name all
# python manage.py create-superuser --username initial --role all --email test@opengxp.org
python manage.py runserver