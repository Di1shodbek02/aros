import random
from django.contrib.auth.tokens import default_token_generator
from django.utils.encoding import force_bytes
from django.utils.encoding import force_str
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from dotenv import load_dotenv
from passlib.context import CryptContext
from rest_framework.generics import CreateAPIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken

from accounts.serializers import UserSerializer, PasswordResetRequestSerializer, \
    PasswordResetLoginSerializer, RegisterSerializer
from accounts.tasks import send_email, send_forget_password

load_dotenv()
pwd_context = CryptContext(schemes=['bcrypt'], deprecated='auto')

from django.core.cache import cache
from rest_framework.response import Response
from rest_framework import status
from rest_framework.generics import GenericAPIView
from .serializers import ConfirmationSerializer
from .models import User


class RegisterAPIView(CreateAPIView):
    serializer_class = RegisterSerializer

    def generate_confirmation_code(self):
        return random.randrange(10000, 90000)

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data['email']
        first_name = serializer.validated_data['first_name']
        last_name = serializer.validated_data['last_name']
        username = serializer.validated_data['username']
        password = serializer.validated_data['password']
        gender = serializer.validated_data['gender']
        phone_number = serializer.validated_data['phone_number']

        confirmation_code = self.generate_confirmation_code()

        cache_data = {
            'email': email,
            'first_name': first_name,
            'last_name': last_name,
            'username': username,
            'password': password,
            'phone_number': phone_number,
            'gender': gender,
            'confirmation_code': confirmation_code,
        }

        cache.set(email, cache_data, timeout=300)
        send_email.delay(email, confirmation_code)
        return Response({'confirmation_code': confirmation_code}, status=status.HTTP_200_OK)




class ConfirmationCodeAPIView(GenericAPIView):
    serializer_class = ConfirmationSerializer

    def post(self, request, *args, **kwargs):
        email = request.data.get('email')
        confirmation_code = request.data.get('confirmation_code')
        cashed_data = cache.get(email)

        if not cashed_data:
            return Response({'success': False, 'message': 'Kod eskirgan yoki mavjud emas!'}, status=status.HTTP_400_BAD_REQUEST)

        if confirmation_code != cashed_data.get('confirmation_code'):
            return Response({'success': False, 'message': 'Kod noto‘g‘ri!'}, status=status.HTTP_400_BAD_REQUEST)

        username = cashed_data.get('username')
        password = cashed_data.get('password')
        first_name = cashed_data.get('first_name')
        last_name = cashed_data.get('last_name')
        phone_number = cashed_data.get('phone_number')
        gender = cashed_data.get('gender')

        if User.objects.filter(email=email).exists():
            return Response({'success': False, 'message': 'This Email already exists!'}, status=status.HTTP_400_BAD_REQUEST)

        if User.objects.filter(username=username).exists():
            return Response({'success': False, 'message': 'This Username already exists!'}, status=status.HTTP_400_BAD_REQUEST)

        user = User.objects.create_user(
            username=username,
            first_name=first_name,
            last_name=last_name,
            phone_number=phone_number,
            gender=gender,
            email=email,
            password=password,
        )

        return Response({'success': True, 'message': 'User created successfully'}, status=status.HTTP_201_CREATED)


class PasswordResetRequestView(GenericAPIView):
    serializer_class = PasswordResetRequestSerializer

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            try:
                user = User.objects.get(email=email)
            except User.DoesNotExist:
                return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

            uid = urlsafe_base64_encode(force_bytes(str(user.pk)))
            token = default_token_generator.make_token(user)
            reset_link = f"http://127.0.0.1:8000/accounts/reset-password/{uid}/{token}/"
            send_forget_password.delay(email, reset_link)
            return Response({'success': 'Password reset link sent'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class PasswordResetView(GenericAPIView):
    serializer_class = PasswordResetLoginSerializer

    def post(self, request, uid, token):

        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            new_password = serializer.validated_data['new_password']

            try:
                uid = force_str(urlsafe_base64_decode(uid))
                user = User.objects.get(pk=uid)
            except (TypeError, ValueError, OverflowError, User.DoesNotExist):
                user = None
            if user is not None and default_token_generator.check_token(user, token):
                user.set_password(new_password)
                user.save()
                return Response({'success': 'Password reset successfully'}, status=status.HTTP_200_OK)
            else:
                return Response({'error': 'Invalid token'}, status=status.HTTP_400_BAD_REQUEST)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



class UserInfo(APIView):
    permission_classes = (IsAuthenticated,)

    def get(self, request):
        user = request.user
        user_serializer = UserSerializer(user)
        return Response(user_serializer.data)


class LogoutAPIView(APIView):
    pеrmission_classes = (IsAuthenticated,)

    def post(self, request):
        rеfresh_token = request.data.get('refresh')
        token = RefreshToken(rеfresh_token)
        token.blacklist()
        return Response(status=204)