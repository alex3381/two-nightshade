from django.db import models
from django.contrib.auth.models import (PermissionsMixin, AbstractBaseUser, BaseUserManager)
from rest_framework_simplejwt.tokens import RefreshToken


class UserManager(BaseUserManager):
    def create_user(self, id, email,  type, password=None, confirm_password=None, **extra_fields):

        if email is None:
            raise TypeError('Users should have an Email')

        if confirm_password is None:
            raise TypeError('Users should have a id')

        user = self.model(id=id, email=self.normalize_email(email), type=type, **extra_fields)
        user.set_password(password)
        user.set_password(confirm_password)

        user.save(using=self._db)
        return user

    def create_superuser(self, id, email, password, confirm_password, **extra_fields):
        if password is None:
            raise TypeError('Password should not be none')

        if confirm_password is None:
            raise TypeError('You must Confirm Password')

        user = self.create_user(id, email, password=password, confirm_password=confirm_password,
                                **extra_fields)

        user.is_superuser = True
        user.is_staff = True
        user.admin = True
        user.save(using=self._db)

        return user


class User(AbstractBaseUser, PermissionsMixin):
    id = models.BigAutoField(primary_key=True, )
    email = models.EmailField(max_length=150, unique=True, db_index=True)
    confirm_password = models.CharField(max_length=8, )
    name = models.CharField(max_length=150, blank=True)
    type = models.TextField(max_length=150)
    is_verified = models.BooleanField(default=False),
    is_active = models.BooleanField(default=True),
    is_staff = models.BooleanField(default=False),
    created_at = models.DateTimeField(auto_now_add=True),
    updated_at = models.DateTimeField(auto_now=True),

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = [ 'id', 'name', 'password', 'confirm_password', 'type', ]

    objects = UserManager()

    def __str__(self):
        return self.email

    def tokens(self):
        refresh = RefreshToken.for_user(self)
        return {
            'refresh': str(refresh),
            'access': str(refresh.access_token)
        }
