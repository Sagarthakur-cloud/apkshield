from django.urls import path
from . import views

urlpatterns = [
    # Auth
    path("login/", views.login_view, name="login"),
    path("signup/", views.signup_view, name="signup"),
    path("logout/", views.logout_view, name="logout"),

    # Pages
    path("", views.dashboard_view, name="dashboard"),
    path("history/", views.history_view, name="history"),
    path("report/", views.report_view, name="report"),
    path("threats/", views.threats_view, name="threats"),
    path("settings/", views.settings_view, name="settings"),
    path("about/", views.about_view, name="about"),

    # API
    path("api/scan/", views.api_scan_apk, name="api_scan"),
    path("api/history/", views.api_history, name="api_history"),
]