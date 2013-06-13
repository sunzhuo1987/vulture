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
        'NAME': '/opt/vulture/admin/db',                      # Or path to database file if using sqlite3.
        'USER': '',                      # Not used with sqlite3.
        'PASSWORD': '',                  # Not used with sqlite3.
        'HOST': '',                      # Set to empty string for localhost. Not used with sqlite3.
        'PORT': '',                      # Set to empty string for default. Not used with sqlite3.
    }
}
FIXTURE_DIRS = (
   '/opt/vulture/admin/fixtures/',
)

HTTPD_PATH = 'sudo /usr/sbin/httpd'
BIN_PATH = '/opt/vulture/bin/'

CONF_PATH = '/opt/vulture/conf/'
DATABASE_PATH = '/opt/vulture/admin/'
SERVERROOT = '/etc/httpd'
HTTPD_CUSTOM = ""

WWW_USER='apache'
WWW_GROUP='apache'

PERL_SWITCHES = '-I/opt/vulture/lib/i386-linux-thread-multi -I/opt/vulture/lib/i386-linux-thread-multi/Vulture -I/opt/vulture/lib/x86_64-linux-thread-multi -I/opt/vulture/lib/i486-linux-thread-multi -I/opt/vulture/lib/i586-linux-thread-multi -I/opt/vulture/lib/i486-linux-gnu-thread-multi -I/opt/vulture/lib -I/opt/vulture/usr/local/lib64/perl5 -I/opt/vulture/usr/lib/perl5 -I/opt/vulture/usr/lib64/perl5 -I/opt/vulture/usr/lib64/perl5/site_perl/5.8.8/x86_64-linux-thread-multi/Apache2'


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
MEDIA_ROOT = '/opt/vulture/static/'

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
        '/opt/vulture/admin',
)

INSTALLED_APPS = (
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.auth',
    'admin.vulture',
#    'django_evolution',
)

AUTHENTICATION_BACKENDS = (
   'vulture.auth.sql',
)

EMAIL_HOST='127.0.0.1'
