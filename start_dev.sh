#!/usr/bin/env bash

rm data/db.sqlite3
rm urp/migrations/*
rm basics/migrations/*
export DJANGO_SETTINGS_MODULE=forms.settings.dev
python manage.py makemigrations
python manage.py makemigrations basics
python manage.py makemigrations urp
python manage.py migrate
python manage.py initialize-settings
python manage.py initialize-status
python manage.py collect-permissions

# create initial role
while true; do
  read -p "Enter role: " role
  if [[ ! -z "$role" && "$role" =~ ^([A-Za-z])+$ ]]; then
    break
  else
    echo "Role must not be empty and must match pattern A-Za-z"
  fi
done

python manage.py create-role --name $role

# create initial user
while true; do
  read -p "Enter initial username: " username
  if [[ ! -z "$username" && "$username" =~ ^([A-Za-z])+$ ]]; then
    break
  else
    echo "Username must not be empty and must match pattern A-Za-z"
  fi
done

while true; do
  while true; do
    read -s -p "Enter initial password with at least 12 characters: " pw
    echo
    if [[ ! -z "$pw" && $(echo ${#pw}) -gt 11 ]]; then
      break
    else
      echo "Password must not be empty and at least 12 characters long"
    fi
  done
  read -s -p "Repeat initial password: " pw2
  echo
  [ "$pw" = "$pw2" ] && break
  echo "Passwords did not match, please try again"
done


while true; do
  read -p "Enter initial email: " email
  if [[ ! -z "$email" && "$email" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,4}$ ]]; then
    break
  else
    echo "Email must not be empty and must match pattern xxx@xxx.xxx"
  fi
done

python manage.py create-superuser --username $username --password $pw --role $role --email $email

# start dev server
python manage.py runserver