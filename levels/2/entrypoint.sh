#!/bin/sh

# Run the init script.
python init_app.py

# Then exec into wsgi
exec gunicorn -w 4 -b ":3000" "app:app"
