# Assignment 2: When a Wreck Reaches the World Wide Web
# Module 1: Getting Setup

## Introduction
Your company hired Shoddycorp's Cut-Rate Contracting to create a gift card website. The code needs significant improvement, and you must fix it.

## Environment Setup
1. Use git with descriptive commit messages. Commits must be signed.
2. Required tools: Python 3, Django, and optionally SQLite, Burp Suite.

## Setup Steps
1. Create appropriate `.gitignore` for Python/Django projects
2. Setup Django:
```
python3 manage.py makemigrations LegacySite
python3 manage.py migrate
python3 manage.py shell -c 'import import_dbs'
```
3. Run the server:
```
python3 manage.py runserver
```

## GitHub Actions
Configure a workflow in `.github/workflows/` that:
- Sets up Python environment
- Installs dependencies
- Runs database migrations
- Executes basic tests