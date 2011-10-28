# Django settings for www project.

DEBUG = False
TEMPLATE_DEBUG = DEBUG

ADMINS = (
    #('Your Name', 'your_email@domain.com'),
)

MANAGERS = ADMINS

DATABASE_ENGINE = 'sqlite3'           # 'postgresql', 'mysql', 'sqlite3' or 'ado_mssql'.
DATABASE_NAME = '/opt/vulture/admin/db'              # Or path to database file if using sqlite3.
DATABASE_USER = ''             # Not used with sqlite3.
DATABASE_PASSWORD = ''         # Not used with sqlite3.
DATABASE_HOST = ''             # Set to empty string for localhost. Not used with sqlite3.
DATABASE_PORT = ''             # Set to empty string for default. Not used with sqlite3.

HTTPD_PATH = 'sudo /opt/vulture/httpd/bin/httpd'
BIN_PATH = '/opt/vulture/bin/'


CONF_PATH = '/opt/vulture/conf/'
DATABASE_PATH = '/opt/vulture/admin/'
BIN_PATH = '/opt/vulture/bin/'
SERVERROOT = '/opt/vulture/httpd'
HTTPD_CUSTOM = "\n\
"

WWW_USER='apache'

PERL_SWITCHES = '-I/opt/vulture/lib/i386-linux-thread-multi -I/opt/vulture/lib/i386-linux-thread-multi/Vulture -I/opt/vulture/lib/i486-linux-thread-multi -I/opt/vulture/lib/i486-linux-gnu-thread-multi -I/opt/vulture/lib'


# Local time zone for this installation. All choices can be found here:
# http://www.postgresql.org/docs/current/static/datetime-keywords.html#DATETIME-TIMEZONE-SET-TABLE
TIME_ZONE = 'America/Chicago'


# Language code for this installation. All choices can be found here:
# http://www.w3.org/TR/REC-html40/struct/dirlang.html#langcodes
# http://blogs.law.harvard.edu/tech/stories/storyReader$15
LANGUAGE_CODE = 'en'

SITE_ID = 1

# Absolute path to the directory that holds media.
# Example: "/home/media/media.lawrence.com/"
MEDIA_ROOT = '/opt/vulture/admin/static/'

# URL that handles the media served from MEDIA_ROOT.
# Example: "http://media.lawrence.com"
MEDIA_URL = '/static/'

# URL prefix for admin media -- CSS, JavaScript and images. Make sure to use a
# trailing slash.
# Examples: "http://foo.com/media/", "/media/".
ADMIN_MEDIA_PREFIX = '/media/'

# Make this unique, and don't share it with anybody.
SECRET_KEY = '(fk$)9xg!#3y@!j)y9u!nn)zm(u-zqbdbb6_s!urdb%8v^cv9m'

# List of callables that know how to import templates from various sources.
TEMPLATE_LOADERS = (
    'django.template.loaders.filesystem.load_template_source',
    'django.template.loaders.app_directories.load_template_source',
#     'django.template.loaders.eggs.load_template_source',
)

MIDDLEWARE_CLASSES = (
    'django.middleware.common.CommonMiddleware',
    'django.middleware.locale.LocaleMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.middleware.doc.XViewMiddleware',
)

ROOT_URLCONF = 'admin.urls'

TEMPLATE_DIRS = (
        '/opt/vulture/admin',
)

INSTALLED_APPS = (
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.auth',
    'admin.vulture',
)

AUTHENTICATION_BACKENDS = (
    'vulture.auth.sql',
)

EMAIL_HOST='127.0.0.1'
