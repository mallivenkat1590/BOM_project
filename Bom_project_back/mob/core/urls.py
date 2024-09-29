from knox import views as knox_views
from .views import LoginAPI, RegisterAPI, UserAPI,PasswordReset,ResetPasswordAPI
from django.urls import path

urlpatterns = [
    path('api/register/', RegisterAPI.as_view(), name='register'),
    path('api/login/', LoginAPI.as_view(), name='login'),
    path('api/logout/', knox_views.LogoutView.as_view(), name='logout'),
    path('api/logoutall/', knox_views.LogoutAllView.as_view(), name='logoutall'),
    path('api/user/', UserAPI.as_view(), name='user'), 
    path("password-reset", PasswordReset.as_view(), name="password-reset"),
    path("password-reset/<str:encoded_pk>/<str:token>/", ResetPasswordAPI.as_view(), name="reset-password"),


]
