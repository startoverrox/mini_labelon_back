import datetime

from django.contrib.auth.models import (
    AbstractBaseUser,
    BaseUserManager,
    PermissionsMixin,
)
from django.db import models


class MemberManager(BaseUserManager):
    def create_user(self, role, name, email, password=None):
        now = datetime.datetime.now()
        user = self.model(
            role=role,
            name=name,
            email=email,
            created_at=now,
            updated_at=now,
        )
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, role, name, email, password=None):
        now = datetime.datetime.now()
        user = self.create_user(
            role=role,
            name=name,
            email=email,
            created_at=now,
            updated_at=now,
        )
        user.is_superuser = True
        user.is_staff = True
        user.set_password(password)
        user.save(using=self._db)
        return user


class Member(AbstractBaseUser, PermissionsMixin):
    role = models.CharField(max_length=255)
    name = models.CharField(max_length=255)
    email = models.EmailField(max_length=255, unique=True)
    password = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_superuser = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)
    last_login = models.DateTimeField(null=True, blank=True)
    objects = MemberManager()
    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["role", "name", "password"]

    class Meta:
        managed = True
        db_table = "member"
