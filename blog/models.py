from datetime import time
from django.db import models
from django.db.models.deletion import CASCADE
from django.contrib.auth.models import User
from django.utils import timezone
# Create your models here.

class PortDetails(models.Model):
    port = models.IntegerField()
    def __str__(self):
        return str(self.port)

class Blacklist(models.Model):
    ip_address = models.CharField(max_length=15)

    def __str__(self):
        return str(self.ip_address)

class Whitelist(models.Model):
    ip_address = models.CharField(max_length=15)
    
    def __str__(self):
        return str(self.ip_address)
