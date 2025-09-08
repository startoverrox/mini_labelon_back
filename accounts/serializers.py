import datetime

from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError as DjangoValidationError
from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer

from accounts.models import Member


class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    def validate(self, attrs):
        data = super().validate(attrs)
        refresh = self.get_token(self.user)
        data["refresh"] = str(refresh)
        data["access"] = str(refresh.access_token)

        return data

    @classmethod
    def get_token(cls, user):
        token = super(CustomTokenObtainPairSerializer, cls).get_token(user)

        token["role"] = user.role
        token["name"] = user.name
        token["email"] = user.email

        return token


class CreateMemberSerializer(serializers.ModelSerializer):
    password = serializers.CharField(
        write_only=True,
        required=True,
        error_messages={
            "required": "비밀번호를 입력해주세요.",
            "blank": "비밀번호를 입력해주세요.",
        },
    )
    password_confirm = serializers.CharField(
        write_only=True,
        required=True,
        error_messages={
            "required": "비밀번호 확인을 입력해주세요.",
            "blank": "비밀번호 확인을 입력해주세요.",
        },
    )

    def validate_email(self, value):
        if Member.objects.filter(email=value).exists():
            raise serializers.ValidationError("이미 존재하는 이메일입니다.")
        return value

    def validate_password(self, value):
        try:
            validate_password(value)
        except DjangoValidationError:
            raise serializers.ValidationError(
                "비밀번호가 보안 요구사항을 충족하지 않습니다. (8자 이상, 숫자, 문자, 특수문자 포함)"
            )
        return value

    def validate(self, attrs):
        if attrs["password"] != attrs["password_confirm"]:
            raise serializers.ValidationError("비밀번호가 일치하지 않습니다.")
        return attrs

    def create(self, validated_data):
        now = datetime.datetime.now()

        member = Member.objects.create(
            role=validated_data["role"],
            name=validated_data["name"],
            email=validated_data["email"],
            created_at=now,
            updated_at=now,
        )
        member.set_password(validated_data["password"])
        member.save()
        return member

    class Meta:
        model = Member
        fields = ["id", "role", "name", "email", "password", "password_confirm"]
        extra_kwargs = {
            "email": {
                "validators": [],
                "error_messages": {
                    "required": "이메일을 입력해주세요.",
                    "invalid": "올바른 이메일 형식을 입력해주세요.",
                    "blank": "이메일을 입력해주세요.",
                },
            },
            "name": {
                "error_messages": {
                    "required": "이름을 입력해주세요.",
                    "blank": "이름을 입력해주세요.",
                }
            },
            "role": {
                "error_messages": {
                    "required": "역할을 선택해주세요.",
                    "blank": "역할을 선택해주세요.",
                }
            },
        }
