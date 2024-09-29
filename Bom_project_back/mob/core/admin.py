from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as DefaultUserAdmin
from django.utils.translation import gettext_lazy as _
from .views import PasswordReset  
from django.contrib.auth.models import User
from .serializers import UserSerializer, RegisterSerializer, ChangePasswordSerializer, EmailSerializer, ResetPasswordSerializer

# Unregister the default UserAdmin
admin.site.unregister(User)

class UserAdmin(DefaultUserAdmin):
    list_display = ('email', 'username', 'name', 'is_staff', 'is_active')
    list_filter = ('is_staff', 'is_superuser', 'is_active', 'groups')
    search_fields = ('email', 'username', 'name')
    ordering = ('email',)

    fieldsets = (
        (None, {'fields': ('username', 'password')}),
        (_('Personal info'), {'fields': ('name', 'email')}),
        (_('Permissions'), {'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions')}),
        (_('Important dates'), {'fields': ('last_login', 'date_joined')}),
        (_('Password Reset Info'), {'fields': ('reset_password_token', 'reset_password_token_created_at')}),
    )

    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'username', 'name', 'password1', 'password2', 'is_staff', 'is_active')}
        ),
    )

    def has_add_permission(self, request):
        return request.user.has_perm('auth.add_user')

    def has_view_permission(self, request, obj=None):
        return request.user.has_perm('auth.view_user')

    def has_change_permission(self, request, obj=None):
        return request.user.has_perm('auth.change_user')

    def has_delete_permission(self, request, obj=None):
        return request.user.has_perm('auth.delete_user')

    @admin.action(description='Reset user password')
    def reset_user_password(self, request, queryset):
        for user in queryset:
            # Logic for resetting password (e.g., setting a new password or sending a reset link)
            # user.set_password('new_password')  # Uncomment and replace with logic to set a new password
            # user.save()
            # Optionally notify the user via email
            self.message_user(request, f"Password for {user.username} has been reset.")

admin.site.register(User, UserAdmin)

@admin.register(PasswordReset)
class PasswordResetAdmin(admin.ModelAdmin):
    list_display = ('user', 'token', 'created_at', 'expired_at')
    search_fields = ('user__email', 'user__username', 'token')
    list_filter = ('created_at', 'expired_at')

    def has_add_permission(self, request):
        return request.user.has_perm('auth.add_passwordreset')

    def has_view_permission(self, request, obj=None):
        return request.user.has_perm('auth.view_passwordreset')

    def has_change_permission(self, request, obj=None):
        return request.user.has_perm('auth.change_passwordreset')

    def has_delete_permission(self, request, obj=None):
        return request.user.has_perm('auth.delete_passwordreset')
