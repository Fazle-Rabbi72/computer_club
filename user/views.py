from django.shortcuts import render, redirect
from rest_framework import viewsets, status
from .models import User
from .serializers import UserSerializer, RegistrationSerializer, UserLoginSerializer, ChangePasswordSerializer
from rest_framework.views import APIView
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes,force_str
from rest_framework.response import Response
from django.contrib.auth import authenticate, login, logout,get_user_model
from rest_framework.authtoken.models import Token
from django.contrib.auth.tokens import default_token_generator
from rest_framework.permissions import IsAuthenticated
from rest_framework.authentication import TokenAuthentication
from django.http import JsonResponse
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.contrib.auth.models import update_last_login
from django.contrib.auth.hashers import make_password
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth.models import update_last_login
from django.core.exceptions import ValidationError



from django.core.mail import send_mail



class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer


class UserRegistrationView(APIView):
    def post(self, request):
        serializer = RegistrationSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            token = default_token_generator.make_token(user)
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            confirm_link = f"https://computer-club.onrender.com/users/activate/{uid}/{token}/"
            email_subject = "Confirm Your Email"
            email_body = render_to_string('confirm_mail.html', {"confirm_link": confirm_link})
            email = EmailMultiAlternatives(email_subject, '', to=[user.email])
            email.attach_alternative(email_body, "text/html")
            email.send()
            return Response({"message": "User registered successfully. Please check your email to activate your account."}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


def activate_account(request, uidb64, token):
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None
        
    if user is not None and default_token_generator.check_token(user, token):
        user.is_active = True
        user.save()
        context = {'success': True, 'message': 'User activated successfully.'}
    else:
        context = {'success': False, 'message': 'Activation link is invalid.'}
    
    # Check if the request is AJAX
    if request.headers.get('x-requested-with') == 'XMLHttpRequest':
        return JsonResponse(context)
    return render(request, 'activation_response.html', context)   
   


class UserLoginApiView(APIView):
    def post(self, request):
        serializer = UserLoginSerializer(data=request.data)
        if serializer.is_valid():
            username = serializer.validated_data.get('username')
            password = serializer.validated_data.get('password')
            user = authenticate(username=username, password=password)
            if user:
                if not user.is_active:
                    return Response({"error": "User is not active."}, status=status.HTTP_401_UNAUTHORIZED)
                if user.status == 'Pending':
                    return Response({"error": "User is not approved yet."}, status=status.HTTP_401_UNAUTHORIZED)
                
                token, _ = Token.objects.get_or_create(user=user)
                login(request, user)
                return Response({'token': token.key, 'user_id': user.id, 'username': user.username}, status=status.HTTP_200_OK)
            return Response({"error": "Invalid credentials."}, status=status.HTTP_401_UNAUTHORIZED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LogoutAPIView(APIView):
    permission_classes = [IsAuthenticated]
    def post(self, request):
        request.user.auth_token.delete()
        logout(request)
        return Response({"message": "Successfully logged out."}, status=status.HTTP_200_OK)


class ChangePasswordView(APIView):
    def post(self, request):
        serializer = ChangePasswordSerializer(data=request.data)
        if serializer.is_valid():
            user = request.user
            old_password = serializer.validated_data.get('old_password')
            new_password = serializer.validated_data.get('new_password')
            confirm_password=serializer.validated_data.get('confirm_password')

            if not user.check_password(old_password):
                return Response({"error": "Old password is incorrect."}, status=status.HTTP_400_BAD_REQUEST)

            if new_password != confirm_password:
                return Response({"error": "Passwords do not match."}, status=status.HTTP_400_BAD_REQUEST)

            user.set_password(new_password)
            user.save()
            return Response({"success": "Password changed successfully."}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    
# class ForgotPasswordView(APIView):
#     def post(self, request):
#         email = request.data.get('email')
#         try:
#             user = User.objects.get(email=email)
#         except User.DoesNotExist:
#             return Response({"error": "User with this email does not exist."}, status=status.HTTP_404_NOT_FOUND)

#         # Generate token and UID
#         token = default_token_generator.make_token(user)
#         uid = urlsafe_base64_encode(force_bytes(user.pk))

#         # Create reset link
#         reset_link = f"https://computer-club.onrender.com/reset-password/{uid}/{token}/"

#         # Send reset email
#         send_mail(
#             "Password Reset Request",
#             '',
#             'noreply@yourdomain.com',
#             [email],
#             fail_silently=False,
#             html_message=render_to_string('forgot_password.html', {"user": user, "reset_link": reset_link})
#         )

#         return Response({"success": "Password reset email sent."}, status=status.HTTP_200_OK)

# class ResetPasswordView(APIView):
#     def get(self, request, uidb64, token):
#         try:
#             # Decode user ID from base64
#             uid = force_str(urlsafe_base64_decode(uidb64))
#             user = get_user_model().objects.get(pk=uid)
#         except (TypeError, ValueError, OverflowError, get_user_model().DoesNotExist):
#             return Response({"error": "Invalid link."}, status=400)

#         # Check if the token is valid
#         if not default_token_generator.check_token(user, token):
#             return Response({"error": "Invalid or expired token."}, status=400)

#         # Render the reset password form
#         return render(request, 'reset_password.html', {'uidb64': uidb64, 'token': token})

#     def post(self, request, uidb64, token):
#         try:
#             # Decode user ID from base64
#             uid = force_str(urlsafe_base64_decode(uidb64))
#             user = get_user_model().objects.get(pk=uid)
#         except (TypeError, ValueError, OverflowError, get_user_model().DoesNotExist):
#             return Response({"error": "Invalid link."}, status=400)

#         # Check if the token is valid
#         if not default_token_generator.check_token(user, token):
#             return Response({"error": "Invalid or expired token."}, status=400)

#         # Get new password from the request
#         new_password = request.data.get('new_password')
#         confirm_password = request.data.get('confirm_password')

#         # Ensure passwords match
#         if new_password != confirm_password:
#             return Response({"error": "Passwords do not match."}, status=400)

#         # Validate the new password
#         try:
#             validate_password(new_password, user)
#         except ValidationError as e:
#             return Response({"error": e.messages}, status=400)

#         # Set and save the new password
#         user.set_password(new_password)
#         user.save()

#         return Response({"success": "Password reset successfully."}, status=200)