from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask.ext.script import Manager
from flask.ext.migrate import Migrate, MigrateCommand

app = Flask(__name__)
app.config.from_object('config')

db = SQLAlchemy(app)
migrate = Migrate(app, db)

manager = Manager(app)
manager.add_command('db', MigrateCommand)

if __name__ == '__main__':
    from app import models, views
    from app.admin.views import mod_admin as admin_module
    from app.user.views import mod_user as user_module
    app.register_blueprint(admin_module)
    app.register_blueprint(user_module)
    manager.run()
