"""WSGI entrypoint for production servers (gunicorn, uwsgi, etc.).

Dev use is still `python run.py` (Flask's dev server, with debug=True
so the /admin/* demo endpoints work). This file is what a real WSGI
server imports:

    gunicorn -w 2 -b 0.0.0.0:8000 wsgi:app
"""
from app import create_app

app = create_app()
