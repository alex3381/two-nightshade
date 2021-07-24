from django.contrib import auth
from django.contrib.auth import get_user_model
from rest_framework import serializers
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.tokens import RefreshToken
from sqlparse.compat import text_type
from . import models
from .models import User

UserModel = get_user_model()


class RegisterSerializer(serializers.ModelSerializer):
    tokens = serializers.SerializerMethodField()
    password = serializers.CharField(
        style={'input_type': 'password'},
        max_length=128,
        min_length=6,
        write_only=True,
        label="Password"

    )
    confirm_password = serializers.CharField(
        style={'input_type': 'password'},
        label="Confirm Password",
        max_length=128, min_length=6, write_only=True

    )

    class Meta:
        model = models.User
        fields = ('email', 'password', 'confirm_password', 'name', 'type', 'tokens',)
        extra_kwargs = {
            'password': {'write_only': True},

        }

    def get_tokens(self, user):
        tokens = RefreshToken.for_user(user)
        refresh = text_type(tokens)
        access = text_type(tokens.access_token)
        data = {
            "refresh": refresh,
            "access": access
        }
        return data

    def create(self, validated_data):
        user = User.objects.create(
            type=validated_data [ 'type' ],
            email=validated_data [ 'email' ],
            name=validated_data [ 'name' ],
        )


        password = self.validated_data [ 'password' ]
        confirm_password = self.validated_data [ 'confirm_password' ]

        if password != confirm_password:
            raise serializers.ValidationError({'password': 'Passwords do not match.'})
        user.set_password(password)
        user.save()
        return user


class LoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255, min_length=5)
    password = serializers.CharField(max_length=68, min_length=6, write_only=True)

    tokens = serializers.SerializerMethodField(read_only=True)

    def get_tokens(self, obj):
        user = UserModel.objects.get(email=obj [ 'email' ])

        return {
            'refresh': user.tokens() [ 'refresh' ],
            'access': user.tokens() [ 'access' ]
        }

    class Meta:
        model = UserModel
        fields = [ 'id', 'email', 'password', 'type', 'name','tokens' ]

    def validate(self, attrs):
        email = attrs.get('email', '')
        password = attrs.get('password', '')
        user = auth.authenticate(email=email, password=password, )

        if not user:
            raise AuthenticationFailed('Invalid Credentials Provided, try again')

        if not user.is_active:
            raise AuthenticationFailed('Account Disabled, Contact Support')

        if not user.is_verified:
            raise AuthenticationFailed('Email is not Verified')
        return {
            'email': user.email,
            'id': user.id,
            'type': user.type,
            'name': user.name,
            'tokens': user.tokens,

        }

        return super().validate(attrs),
