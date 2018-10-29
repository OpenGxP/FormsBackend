#!/usr/bin/env bash

rm  db.sqlite3
rm UserRolesPermissions/migrations/*
python manage.py makemigrations
python manage.py makemigrations UserRolesPermissions
python manage.py migrate
export DJANGO_SETTINGS_MODULE=forms.settings
python fixtures.py
python manage.py loaddata status
python manage.py createsuperuser --username superuser
python manage.py runserver