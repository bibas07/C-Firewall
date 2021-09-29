import re
from sys import maxsize
from django.contrib import messages
from django.db import models
from django.contrib.auth.models import User
# Create your models here.\

class TargetHost(models.Model):
    host = models.CharField(max_length=30)

    def __str__(self):
        return self.host

class IPscanModel(models.Model):
    first_ip = models.CharField(max_length=16)
    last_ip = models.CharField(max_length=16)
    user = models.ForeignKey(User, on_delete=models.CASCADE)

    def __str__(self):
        return self.user

class DdosModel(models.Model):
    host = models.CharField(max_length=20)
    port = models.IntegerField(max_length=5)
    msg = models.TextField(max_length=200)
    req_num = models.IntegerField(max_length=100000)

    def __str__(self):
        return self.host

