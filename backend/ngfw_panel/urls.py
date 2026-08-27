from django.contrib import admin
from django.contrib.auth import views as auth_views
from django.urls import include, path

urlpatterns = [
    path("admin/", admin.site.urls),
    path("api/v1/", include("policies.urls")),

    path(
        "login/",
        auth_views.LoginView.as_view(
            template_name="policies/login.html"
        ),
        name="login",
    ),
    path(
        "logout/",
        auth_views.LogoutView.as_view(),
        name="logout",
    ),
    path(
        "password-change/",
        auth_views.PasswordChangeView.as_view(
            template_name="policies/password_change.html"
        ),
        name="password_change",
    ),
    path(
        "password-change/done/",
        auth_views.PasswordChangeDoneView.as_view(
            template_name="policies/password_change_done.html"
        ),
        name="password_change_done",
    ),

    path("", include("policies.web_urls")),
]
