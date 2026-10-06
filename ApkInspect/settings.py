"""
Django settings for ApkInspect project.
Production-ready for Render.com deployment.
"""

import os
import dj_database_url
from pathlib import Path

# ═══════════════════════════════════════════════
# BASE PATHS
# ═══════════════════════════════════════════════
BASE_DIR = Path(__file__).resolve().parent.parent


# ═══════════════════════════════════════════════
# SECURITY
# ═══════════════════════════════════════════════
SECRET_KEY = os.environ.get(
    "SECRET_KEY",
    "django-insecure-dev-fallback-change-me-in-production"
)

DEBUG = os.environ.get("DEBUG", "False").lower() == "true"

ALLOWED_HOSTS = os.environ.get(
    "ALLOWED_HOSTS",
    "*"
).split(",")


# ═══════════════════════════════════════════════
# APPLICATIONS
# ═══════════════════════════════════════════════
INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "app",
]


# ═══════════════════════════════════════════════
# MIDDLEWARE (whitenoise after security)
# ═══════════════════════════════════════════════
MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]


# ═══════════════════════════════════════════════
# URLS & WSGI
# ═══════════════════════════════════════════════
ROOT_URLCONF = "ApkInspect.urls"

WSGI_APPLICATION = "ApkInspect.wsgi.application"


# ═══════════════════════════════════════════════
# TEMPLATES
# ═══════════════════════════════════════════════
TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "app" / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]


# ═══════════════════════════════════════════════
# DATABASE
# ═══════════════════════════════════════════════
# Uses DATABASE_URL env var on Render (PostgreSQL)
# Falls back to SQLite for local development
DATABASES = {
    "default": dj_database_url.config(
        default=f"sqlite:///{BASE_DIR / 'db.sqlite3'}",
        conn_max_age=600,
        conn_health_checks=True,
    )
}


# ═══════════════════════════════════════════════
# PASSWORD VALIDATION
# ═══════════════════════════════════════════════
AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]


# ═══════════════════════════════════════════════
# INTERNATIONALIZATION
# ═══════════════════════════════════════════════
LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True


# ═══════════════════════════════════════════════
# STATIC FILES (WhiteNoise)
# ═══════════════════════════════════════════════
STATIC_URL = "/static/"
STATICFILES_DIRS = [BASE_DIR / "static"]
STATIC_ROOT = BASE_DIR / "staticfiles"

# WhiteNoise compressed storage for production
if not DEBUG:
    STATICFILES_STORAGE = "whitenoise.storage.CompressedManifestStaticFilesStorage"
else:
    STATICFILES_STORAGE = "django.contrib.staticfiles.storage.StaticFilesStorage"


# ═══════════════════════════════════════════════
# MEDIA FILES (user uploads)
# ═══════════════════════════════════════════════
MEDIA_URL = "/media/"
MEDIA_ROOT = BASE_DIR / "media"


# ═══════════════════════════════════════════════
# DEFAULT PRIMARY KEY
# ═══════════════════════════════════════════════
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"


# ═══════════════════════════════════════════════
# AUTH REDIRECTS
# ═══════════════════════════════════════════════
LOGIN_URL = "login"
LOGIN_REDIRECT_URL = "dashboard"
LOGOUT_REDIRECT_URL = "welcome"


# ═══════════════════════════════════════════════
# CSRF TRUSTED ORIGINS (for Render)
# ═══════════════════════════════════════════════
CSRF_TRUSTED_ORIGINS = os.environ.get(
    "CSRF_TRUSTED_ORIGINS",
    "https://*.onrender.com,http://localhost:8000,http://127.0.0.1:8000"
).split(",")


# ═══════════════════════════════════════════════
# FILE UPLOAD LIMITS (100 MB max)
# ═══════════════════════════════════════════════
DATA_UPLOAD_MAX_MEMORY_SIZE = 100 * 1024 * 1024  # 100 MB
FILE_UPLOAD_MAX_MEMORY_SIZE = 100 * 1024 * 1024  # 100 MB


# ═══════════════════════════════════════════════
# SECURITY HEADERS (production only)
# ═══════════════════════════════════════════════
if not DEBUG:
    SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
    SESSION_COOKIE_SECURE = True
    CSRF_COOKIE_SECURE = True
    SECURE_BROWSER_XSS_FILTER = True
    SECURE_CONTENT_TYPE_NOSNIFF = True


# ═══════════════════════════════════════════════
# LOGGING (helpful for debugging on Render)
# ═══════════════════════════════════════════════
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
        },
    },
    "root": {
        "handlers": ["console"],
        "level": "INFO",
    },
}