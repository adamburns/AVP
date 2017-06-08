#!/usr/bin/python
import sys
import logging
logging.basicConfig(stream=sys.stderr)
sys.path.insert(0,"/var/www/")

from app import app
from werkzeug.debug import DebuggedApplication
application = DebuggedApplication(app, True)
application.secret_key = 'd6a2f8981c6848f257ebc0cb75c822a98dd2150981'
