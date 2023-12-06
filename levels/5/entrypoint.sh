#!/bin/sh

# Run the init script.
python init_app.py

# if the DEV_MODE env var is not blank...
if [ -n "$DEV_MODE" ]; then
    # ... execute the flask dev command.
    exec python app.py
fi

# Then exec into wsgi
exec gunicorn -w 4 -b ":3000" "app:app"
