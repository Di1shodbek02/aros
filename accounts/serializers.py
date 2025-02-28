from rest_framework import serializers
from rest_framework.serializers import ModelSerializer, Serializer

from accounts.models import User

class RegisterSerializer(ModelSerializer):
    class Meta:
        model = User
        fields = ('username', 'first_name', 'last_name', 'email', 'gender')

class ConfirmationSerializer(Serializer):
    email = serializers.EmailField()
    confirmation_code = serializers.IntegerField()

class PasswordResetRequestSerializer(serializers.Serializer):
    email = serializers.EmailField()


class PasswordResetLoginSerializer(serializers.Serializer):
    new_password = serializers.CharField()

class UserListSerializer(ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'email', 'username', 'phone_number', 'gender']

class UpdateUserSerializer(ModelSerializer):
    class Meta:
        model = User
        fields = ['avatar', 'first_name', 'last_name', 'phone_number', 'gender']


class UserSerializer(ModelSerializer):
    class Meta:
        model = User
        fields = ('avatar', 'username', 'email', 'first_name', 'last_name')