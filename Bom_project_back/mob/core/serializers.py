from rest_framework import serializers
from django.contrib.auth.models import User
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.http import urlsafe_base64_decode

# User Serializer
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('id', 'username', 'email')


# Register Serializer
class RegisterSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('id', 'username', 'email', 'password')
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        user = User.objects.create_user(
            validated_data['username'], 
            validated_data['email'], 
            validated_data['password']
        )
        return user


# Change Password Serializer
class ChangePasswordSerializer(serializers.Serializer):
    """
    Serializer for password change endpoint.
    """
    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True)


# Password Reset Email Request Serializer
class EmailSerializer(serializers.Serializer):
    """
    Serializer for requesting a password reset link via email.
    """
    email = serializers.EmailField()

    class Meta:
        fields = ("email",)


# Reset Password Serializer
class ResetPasswordSerializer(serializers.Serializer):
    """
    Serializer for resetting the user's password using a token.
    """
    password = serializers.CharField(write_only=True, min_length=1)

    class Meta:
        fields = ("password",)

    def validate(self, data):
        """
        Validate the reset token and encoded user id (encoded_pk), then set the new password.
        """
        password = data.get("password")
        token = self.context.get("kwargs").get("token")
        encoded_pk = self.context.get("kwargs").get("encoded_pk")

        if token is None or encoded_pk is None:
            raise serializers.ValidationError("Missing token or user identifier.")

        try:
            pk = urlsafe_base64_decode(encoded_pk).decode()
            user = User.objects.get(pk=pk)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            raise serializers.ValidationError("Invalid user identifier.")

        if not PasswordResetTokenGenerator().check_token(user, token):
            raise serializers.ValidationError("The reset token is invalid or expired.")

        # Set the new password
        user.set_password(password)
        user.save()

        return data
