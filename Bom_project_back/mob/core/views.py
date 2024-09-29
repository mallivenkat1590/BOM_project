from django.contrib.auth import login
from django.contrib.auth.models import User
from rest_framework import generics, permissions, status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.authtoken.serializers import AuthTokenSerializer
from knox.views import LoginView as KnoxLoginView
from knox.models import AuthToken
from .serializers import UserSerializer, RegisterSerializer, ChangePasswordSerializer
from django.views.decorators.debug import sensitive_post_parameters
from django.utils.decorators import method_decorator

# Register API
class RegisterAPI(generics.GenericAPIView):
    serializer_class = RegisterSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        return Response({
            "user": UserSerializer(user, context=self.get_serializer_context()).data,
            "token": AuthToken.objects.create(user)[1]
        })

# Login API
@method_decorator(sensitive_post_parameters('password'), name='dispatch')
class LoginAPI(KnoxLoginView):
    permission_classes = (permissions.AllowAny,)

    def post(self, request, format=None):
        serializer = AuthTokenSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        login(request, user)
        return super(LoginAPI, self).post(request, format=None)

# Get User API
class UserAPI(generics.RetrieveAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = UserSerializer

    def get_object(self):
        return self.request.user



from rest_framework import generics, status, viewsets, response

from django.conf import settings
from django.contrib.auth.models import User
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.urls import reverse
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode

from . import serializers


from django.core.mail import send_mail
from django.conf import settings

class PasswordReset(generics.GenericAPIView):
    """
    Request for Password Reset Link.
    """

    serializer_class = serializers.EmailSerializer

    def post(self, request):
        """
        Create token and send reset link via email.
        """
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.data["email"]
        user = User.objects.filter(email=email).first()
        if user:
            encoded_pk = urlsafe_base64_encode(force_bytes(user.pk))
            token = PasswordResetTokenGenerator().make_token(user)
            reset_url = reverse(
                "reset-password",
                kwargs={"encoded_pk": encoded_pk, "token": token},
            )
            reset_link = f"http://localhost:8000{reset_url}"

            # Send the reset link as an email to the user
            subject = 'Password Reset Request'
            message = f'You requested a password reset. Click the link below to reset your password:\n\n{reset_link}'
            from_email = settings.EMAIL_HOST_USER  # Your email address

            send_mail(subject, message, from_email, [email])

            return response.Response(
                {
                    "message": "Password reset link has been sent to your email."
                },
                status=status.HTTP_200_OK,
            )
        else:
            return response.Response(
                {"message": "If an account with that email exists, we have sent a reset link."},
                status=status.HTTP_400_BAD_REQUEST,
            )

class ResetPasswordAPI(generics.GenericAPIView):
    """
    Verify and Reset Password Token View.
    """

    serializer_class = serializers.ResetPasswordSerializer

    def patch(self, request, *args, **kwargs):
        """
        Verify token & encoded_pk and then reset the password.
        """
        serializer = self.serializer_class(data=request.data, context={"kwargs": kwargs})
        serializer.is_valid(raise_exception=True)

        # Get the user and update the password
        encoded_pk = kwargs["encoded_pk"]
        token = kwargs["token"]

        try:
            user_id = force_bytes(urlsafe_base64_encode(encoded_pk))  # Decode the user id
            user = User.objects.get(pk=user_id)  # Get the user
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            user = None

        if user is not None and PasswordResetTokenGenerator().check_token(user, token):
            # Token is valid, reset the password
            new_password = serializer.validated_data['new_password']
            user.set_password(new_password)
            user.save()

            return response.Response(
                {"message": "Password reset complete"},
                status=status.HTTP_200_OK,
            )
        else:
            return response.Response(
                {"message": "Invalid token or user ID"},
                status=status.HTTP_400_BAD_REQUEST,
            )

