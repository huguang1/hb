#!/usr/bin/python
# -*- coding: utf-8 -*-
# @Author: June
# @Time : 2019/3/2
from rest_framework.permissions import BasePermission


class IsSuperUser(BasePermission):
    """
    Allows access only to Super Admin Sers.
    """

    def has_permission(self, request, view):
        return bool(request.user and request.user.is_superuser)
