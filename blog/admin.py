from django.contrib import admin
from django.contrib.auth import models
from . import models
# Register your models here.
admin.site.register(models.Blacklist)
admin.site.register(models.Whitelist)