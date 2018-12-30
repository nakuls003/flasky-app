import os, sys, click

COV = None
if os.environ.get('FLASKY_COVERAGE'):
    print("FLASK_COVERAGE=" + os.environ.get('FLASKY_COVERAGE'))
    import coverage
    COV = coverage.coverage(branch=True, include='app/*')
    COV.start()


from flask_migrate import Migrate, upgrade
from app import create_app, db
from app.models import User, Role, Follow, Comment, Post


app = create_app(os.environ.get('FLASK_CONFIG') or 'default')
migrate = Migrate(app, db)


@app.cli.command()
@click.option('--coverage/--no-coverage', default=False, help='Run tests under code coverage')
def test(coverage):
    if coverage and not os.environ.get('FLASKY_COVERAGE'):
        os.environ['FLASKY_COVERAGE'] = '1'
        os.execvp(sys.executable, [sys.executable] + sys.argv)
    import unittest
    tests = unittest.TestLoader().discover('tests')
    unittest.TextTestRunner(verbosity=2).run(tests)

    if COV:
        COV.stop()
        COV.save()
        print("Coverage Summary:")
        COV.report()
        base_dir = os.path.abspath(os.path.dirname(__file__))
        html_report_path = os.path.join(base_dir, 'tmp/coverage')
        COV.html_report(directory=html_report_path)
        print("HTML Version: file://{}/index.html".format(html_report_path))
        COV.erase()


@app.cli.command()
@click.option('--length', default=25, help='Number of functions to include in the profiler report')
@click.option('--profile-dir', default=None, help='Directory to store profiler report files')
def profile(length, profile_dir):
    from werkzeug.contrib.profiler import ProfilerMiddleware
    app.wsgi_app = ProfilerMiddleware(app.wsgi_app, restrictions=[length], profile_dir=profile_dir)
    app.run(debug=False)


@app.shell_context_processor
def make_shell_context():
    return dict(db=db, User=User, Role=Role, Follow=Follow, Comment=Comment, Post=Post)


@app.cli.command()
def deploy():
    upgrade()
    Role.insert_roles()
    User.add_self_follows()


# if __name__ == '__main__':
#     app.run()
