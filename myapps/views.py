# Create your views here.

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login
from django.contrib.auth.decorators import user_passes_test
from .models import IndividualExpense
from django.contrib.auth import logout
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import json
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.contrib import messages
from django.contrib.auth.forms import UserCreationForm


from .forms import UserRegisterForm 
def register(request):
    """
    Handles user registration.

    If the request method is POST, it processes the registration form.
    If the form is valid, it creates a new user and redirects to the login page.
    Otherwise, it displays error messages.
    
    Returns:
        HttpResponse: Renders the registration page with the form.
    """
    if request.method == 'POST':
        form = UserRegisterForm(request.POST)
        if form.is_valid():
            form.save() 
            messages.success(request, 'Account created successfully! You can now log in.')
            return redirect('login')
        else:
            messages.error(request, 'Registration failed. Please correct the errors below.', extra_tags='danger')
    else:
        form = UserRegisterForm()

    return render(request, 'register.html', {'form': form})


def user_login(request):
    """
    Handles user login.

    If the request method is POST, it authenticates the user based on the provided credentials.
    If authentication is successful, the user is logged in and redirected to the index page.
    Otherwise, an error message is displayed.

    Returns:
        HttpResponse: Renders the login page.
    """
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
    """
    Renders the home page (index).

    Returns:
        HttpResponse: Renders the index.html template.
    """
    return render(request, 'index.html')

def admin_login(request):
    """
    Handles admin login.

    If the request method is POST, it authenticates the user.
    If the user is an admin (superuser), they are logged in and redirected to the admin dashboard.
    Otherwise, an error message is displayed.

    Returns:
        HttpResponse: Renders the admin login page.
    """
    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")
        user = authenticate(request, username=username, password=password)

        if user is not None and user.is_superuser:
            login(request, user)
            return redirect("admin_dashboard")
        else:
            return render(request, "admin_login.html", {"error": "Invalid credentials or not an admin."})

    return render(request, "admin_login.html")

# Function to check if user is a superuser
def is_superuser(user):
    """
    Checks if the user is a superuser.

    Args:
        user (User): The user object.

    Returns:
        bool: True if the user is authenticated and is a superuser, False otherwise.
    """
    return user.is_authenticated and user.is_superuser


@user_passes_test(is_superuser, login_url='admin_login')  # Restrict non-superusers
def admin_dashboard(request):
    """
    Displays the admin dashboard.

    Only accessible to superusers. Shows a list of all individual expenses and registered users.

    Returns:
        HttpResponse: Renders the admin dashboard page with relevant data.
    """
    personal_expenses = IndividualExpense.objects.all()
    users = User.objects.all()
    context = {
        'personal_expenses': personal_expenses,
        'users': users,
    }

    return render(request, 'admin_dashboard.html', context)


def user_logout(request):
    """
    Logs out the user and redirects to the login page.

    Returns:
        HttpResponseRedirect: Redirects to the login page.
    """
    logout(request)
    return redirect('login')








   