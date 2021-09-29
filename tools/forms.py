from django import forms
from django.forms import fields
from .models import DdosModel, IPscanModel, TargetHost
from tools import models

class TargetForm(forms.ModelForm):

    class Meta:
        model = TargetHost
        fields = ('host',)
    

class IPscanForm(forms.ModelForm):

    class Meta:
        model = IPscanModel
        fields = ['first_ip', 'last_ip']

class DdosForm(forms.ModelForm):

    class Meta:
        model = DdosModel
        fields = ['host','port','msg','req_num']





