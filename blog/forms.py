from django import forms
import django
from django.forms import fields
from . import models
from django.contrib.auth.models import User
class PortForm(forms.ModelForm):
    class Meta:
        model = models.PortDetails
        fields = ('port',)

class BlacklistForm(forms.ModelForm):
    class Meta:
        model = models.Blacklist
        fields = ['ip_address']

class WhitelistForm(forms.ModelForm):
    class Meta:
        model = models.Whitelist
        fields = ['ip_address']
