#!/usr/bin/python
# -*- coding: utf-8 -*-
# @Author: June
# @Time : 2019/2/27
# JWT 自定义配置相关
from rest_framework_jwt.authentication import JSONWebTokenAuthentication
from rest_framework.authentication import (
    BaseAuthentication, get_authorization_header
)
from rest_framework_jwt.settings import api_settings
from django.utils.encoding import smart_text
from rest_framework import exceptions
from django.utils.translation import ugettext as _
from django.contrib.auth.signals import user_logged_in


class JwtAuthentication(JSONWebTokenAuthentication):
    def get_jwt_value(self, request):
        auth = get_authorization_header(request).split()
        auth_header_prefix = api_settings.JWT_AUTH_HEADER_PREFIX.lower()

        if not auth:
            return None  # 当JWT_AUTH_COOKIE的值有设置时，不能从cookie获取值，仅能从header获取

        if smart_text(auth[0].lower()) != auth_header_prefix:
            return None

        if len(auth) == 1:
            msg = _('Invalid Authorization header. No credentials provided.')
            raise exceptions.AuthenticationFailed(msg)
        elif len(auth) > 2:
            msg = _('Invalid Authorization header. Credentials string '
                    'should not contain spaces.')
            raise exceptions.AuthenticationFailed(msg)

        return auth[1]


def jwt_get_user_secret_key(user):
    return user.password


def jwt_response_payload_handler(token, user=None, request=None):
    # 更新user的last_login
    user_logged_in.send(sender=user.__class__, request=request, user=user)
    return {
        'token': token,
        'roles': ['1', '2', '3', '4', '5', '6'] if user.is_superuser else user.role.split('|'),
        'name': user.username
    }
