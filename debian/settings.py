# Django settings for www project.

DEBUG = False
TEMPLATE_DEBUG = DEBUG

ADMINS = (
    #('Your Name', 'your_email@domain.com'),
)

MANAGERS = ADMINS
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3', # Add 'postgresql_psycopg2', 'postgresql', 'mysql', 'sqlite3' or 'oracle'.
        'NAME': '/var/www/vulture/admin/db',                      # Or path to database file if using sqlite3.
        'USER': '',                      # Not used with sqlite3.
        'PASSWORD': '',                  # Not used with sqlite3.
        'HOST': '',                      # Set to empty string for localhost. Not used with sqlite3.
        'PORT': '',                      # Set to empty string for default. Not used with sqlite3.
    }
}
FIXTURE_DIRS = (
   '/var/www/vulture/admin/fixtures/',
)

HTTPD_PATH = 'sudo /usr/sbin/apache2'
BIN_PATH = '/var/www/vulture/bin/'

CONF_PATH = '/var/www/vulture/conf/'
DATABASE_PATH = '/var/www/vulture/admin/'
SERVERROOT = '/usr/lib/apache2'
HTTPD_CUSTOM = ""

SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
SESSION_EXPIRE_AT_BROWSER_CLOSE = True


WWW_USER = 'www-data'
WWW_GROUP = 'www-data'

PERL_SWITCHES = '-I/opt/vulture/lib/i386-linux-thread-multi -I/opt/vulture/lib/i386-linux-thread-multi/Vulture -I/opt/vulture/lib/i486-linux-thread-multi -I/opt/vulture/lib/i486-linux-gnu-thread-multi'


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
MEDIA_ROOT = '/var/www/vulture/static/'

# URL that handles the media served from MEDIA_ROOT.
# Example: "http://media.lawrence.com"
MEDIA_URL = '/static/'

# URL prefix for admin media -- CSS, JavaScript and images. Make sure to use a
# trailing slash.
# Examples: "http://foo.com/media/", "/media/".
ADMIN_MEDIA_PREFIX = '/media/'

# Make this unique, and don't share it with anybody.
SECRET_KEY = ''

# List of callables that know how to import templates from various sources.
TEMPLATE_LOADERS = (
    'django.template.loaders.filesystem.Loader',
    'django.template.loaders.app_directories.Loader',
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
        '/var/www/vulture/admin',
)

INSTALLED_APPS = (
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.auth',
    'admin.vulture',
    'django_evolution',
)

AUTHENTICATION_BACKENDS = (
    'vulture.auth.sql',
)

EMAIL_HOST='127.0.0.1'
