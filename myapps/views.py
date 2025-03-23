from django.shortcuts import render

# Create your views here.

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login
from django.contrib.auth.decorators import user_passes_test
from django.contrib.auth import logout
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import json
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.contrib import messages
from django.contrib.auth.forms import UserCreationForm


def register(request):
    if request.method == 'POST':
        form = UserCreationForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, 'Account created successfully! You can now log in.')
            return redirect('login')
        else:
            # Display form errors
            errors = form.errors.as_json()
            messages.error(request, 'Registration failed.Please correct the errors below.', extra_tags='danger')
    else:
        form = UserCreationForm()
    
    return render(request, 'register.html', {'form': form})

def user_login(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(request, username=username, password=password)

        if user is not None:
            login(request, user)
            return redirect('index')
        else:
            messages.error(request, 'This account is not registered.')
            return redirect('login')
    return render(request, 'login.html')

def index(request):
    return render(request, 'index.html')



