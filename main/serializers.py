#!/usr/bin/python
# -*- coding: utf-8 -*-
# @Author: June
# @Time : 2019/2/27
from .models import Prize, Rule, Rec, Info
from django.contrib.auth import get_user_model
from rest_framework import serializers


class AdminSerializer(serializers.ModelSerializer):

    class Meta:
        model = get_user_model()
        fields = ("id", "username", "is_superuser", "last_login", "password", "role")
        extra_kwargs = {
            "password": {'write_only': True}
        }


class PrizeSerializer(serializers.ModelSerializer):
    class Meta:
        model = Prize
        fields = "__all__"


class RuleSerializer(serializers.ModelSerializer):
    class Meta:
        model = Rule
        fields = "__all__"


class RecSerializer(serializers.ModelSerializer):

    class Meta:
        model = Rec
        fields = "__all__"
        extra_kwargs = {'ip': {'read_only': True}, 'prizeId': {'read_only': True}}


class MemberRecSerializer(serializers.ModelSerializer):

    class Meta:
        model = Rec
        fields = ("user", "prizeName", "prizeId", "datetime", "sendTime", "isSend")
        extra_kwargs = {
            'prizeName': {'read_only': True},
            'prizeId': {'read_only': True},
            'datetime': {'read_only': True},
            'sendTime': {'read_only': True},
            'isSend': {'read_only': True},
        }


class InfoSerializer(serializers.ModelSerializer):
    class Meta:
        model = Info
        fields = "__all__"




