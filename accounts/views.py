from django.conf import settings
from django.shortcuts import render
from rest_framework import generics, status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

from accounts.models import Member
from accounts.serializers import (
    CreateMemberSerializer,
    CustomTokenObtainPairSerializer,
)


class LoginView(TokenObtainPairView):
    permission_classes = (AllowAny,)
    serializer_class = CustomTokenObtainPairSerializer

    def post(self, request, *args, **kwargs):
        response = super().post(request, *args, **kwargs)

        if response.status_code == 200:
            access_token = response.data.get("access")
            refresh_token = response.data.pop("refresh")

            refresh_lifetime = settings.SIMPLE_JWT.get("REFRESH_TOKEN_LIFETIME")
            expiry = int(refresh_lifetime.total_seconds())

            response.data = {
                "success": True,
                "message": "로그인 성공",
                "data": {"access": access_token},
            }

            response.set_cookie(
                key="refreshToken",
                value=refresh_token,
                httponly=True,
                samesite="Strict",
                path="/",
                max_age=expiry,
            )
        else:
            response.data = {
                "success": False,
                "message": "아이디 또는 비밀번호가 올바르지 않습니다.",
            }

        return response


class LogoutView(APIView):
    permission_classes = (AllowAny,)

    def post(self, request):
        response = Response(
            {"success": True, "message": "로그아웃 성공"},
            status=status.HTTP_200_OK,
        )

        # cookie 제거
        response.delete_cookie(key="refreshToken", path="/")
        return response


class TokenRefreshView(TokenRefreshView):
    permission_classes = (AllowAny,)

    def post(self, request, *args, **kwargs):
        refresh_token = request.COOKIES.get("refreshToken")

        if not refresh_token:
            return Response(
                {
                    "success": False,
                    "message": r"인증이 만료되었습니다.\n다시 로그인 해주세요.",
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        # request.data를 수정하여 refresh token 추가
        request.data["refresh"] = refresh_token

        response = super().post(request, *args, **kwargs)

        if response.status_code == 200:
            response.data = {"data": response.data}

        return response


class RegisterView(generics.CreateAPIView):
    permission_classes = (AllowAny,)

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(
                {
                    "success": True,
                    "data": serializer.data,
                    "message": "회원가입 성공",
                },
                status=status.HTTP_201_CREATED,
            )

        return Response(
            {
                "success": False,
                "data": serializer.data,
                "message": "회원가입 실패",
                "errors": serializer.errors,
            },
            status=status.HTTP_400_BAD_REQUEST,
        )
