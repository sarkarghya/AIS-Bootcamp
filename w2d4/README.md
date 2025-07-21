# W2D4

# Assignment 2: When a Wreck Reaches the World Wide Web
# Module 1: Getting Setup

## Introduction
Your AI company hired External Contracting to create a gift card website. Unfortunately it seems the contractors have done a great job. You are assigned to review the code and fix it. If you do not make the necessary changes your company may suffer significant lossses.

## Setup
``` bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Migration
1. Create appropriate `.gitignore` for Python/Django projects
2. Setup Django:
``` bash
python3 manage.py makemigrations LegacySite
python3 manage.py migrate
python3 manage.py shell -c 'import import_dbs'
```
3. Run the server:
``` bash
python3 manage.py runserver
```