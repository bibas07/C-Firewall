from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth.models import User
from django.shortcuts import redirect, render
from .forms import CreateUserForm
from django.contrib.auth.tokens import default_token_generator
from django.utils.encoding import force_bytes, force_text
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib import messages

# Create your views here.
def signup_user(request):
    if request.method== 'POST':
        form = CreateUserForm(request.POST)
        if form.is_valid():
            form.save()
            user = form.cleaned_data.get('username')
            messages.success(request, 'Account created successfully [ %s ]. You have to log in now' %user)
            return redirect('signin')
    else:
        form = CreateUserForm()
    return render(request, 'users/signup.html', {'form':form})
