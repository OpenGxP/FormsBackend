#!/usr/bin/env bash

rm  db.sqlite3
rm urp/migrations/*
rm basics/migrations/*
python manage.py makemigrations
python manage.py makemigrations basics
python manage.py makemigrations urp
python manage.py migrate
export DJANGO_SETTINGS_MODULE=forms.settings
python fixtures.py
python manage.py loaddata status
python manage.py loaddata permissions
python manage.py loaddata roles
python manage.py loaddata settings
python manage.py createsuperuser --username superuser
python manage.py runserver