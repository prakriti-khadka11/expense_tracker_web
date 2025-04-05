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
from .forms import UserRegisterForm
from django.contrib.auth.forms import UserCreationForm
from django.core.mail import EmailMessage, send_mail
from django.contrib.sites.shortcuts import get_current_site

from django.utils.encoding import force_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.template.loader import render_to_string
from django.urls import reverse
from django.contrib import auth
from .utils import account_activation_token

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

def is_superuser(user):
    """
    Checks if the user is a superuser.

    Args:
        user (User): The user object.

    Returns:
        bool: True if the user is authenticated and is a superuser, False otherwise.
    """
    return user.is_authenticated and user.is_superuser

@user_passes_test(is_superuser, login_url='admin_login')
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

def request_password_reset(request):
    if request.method == "POST":
        email = request.POST.get("email")  
        user = User.objects.filter(email=email).first()
        if user:
            current_site = get_current_site(request)
            email_body = {
                'user': user,
                'domain': current_site.domain,
                'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                'token': account_activation_token.make_token(user),
            }
            link = reverse('reset_password_confirm', kwargs={
                           'uidb64': email_body['uid'], 'token': email_body['token']})
            reset_url = 'http://'+current_site.domain+link
            email_subject = 'Reset Your Password'
            email_message = EmailMessage(
                email_subject,
                'Hi '+user.username+', Click the link below to reset your password of your Expense Tracker Website: \n'+reset_url,
                'noreply@yourdomain.com',
                [email],
            )
            email_message.send(fail_silently=False)
            messages.success(request, "A password reset link has been sent to your email.")
            return redirect("login")
        else:
            messages.error(request, "No account found with this email.")
    return render(request, "reset-password.html")


def reset_password_confirm(request, uidb64, token):
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = User.objects.get(pk=uid)
        if account_activation_token.check_token(user, token):
            if request.method == 'POST':
                new_password = request.POST.get('password')
                confirm_password = request.POST.get('confirm_password')
                
                # Check if passwords match
                if new_password != confirm_password:
                    messages.error(request, "The passwords do not match. Please try again.")
                    return render(request, 'reset-password-confirm.html', {'validlink': True})
                
                # Check password length
                if len(new_password) < 8:
                    messages.error(request, "Password must be at least 8 characters long.")
                    return render(request, 'reset-password-confirm.html', {'validlink': True})

                user.set_password(new_password)
                user.save()
                messages.success(request, "Your password has been reset successfully. You can now log in.")
                return redirect('login')
            
            return render(request, 'reset-password-confirm.html', {'validlink': True})
        else:
            messages.error(request, "The password reset link is invalid.")
            return redirect('login')
    except (TypeError, ValueError, OverflowError, User.DoesNotExist, DjangoUnicodeDecodeError):
        messages.error(request, "The password reset link is invalid.")
        return redirect('login')


    
    


def user_logout(request):
    """
    Logs out the user and redirects to the login page.

    Returns:
        HttpResponseRedirect: Redirects to the login page.
    """
    logout(request)
    return redirect('login')

@user_passes_test(is_superuser, login_url='admin_login')
def admin_expense_edit(request, expense_id, is_group):
    # Convert is_group to a boolean
    is_group = True if is_group.lower() == 'true' else False

    expense = get_object_or_404(IndividualExpense, id=expense_id)

    # Handle form submission (POST request)
    if request.method == "POST":
        expense.name = request.POST.get("name")
        expense.amount = request.POST.get("amount")
        expense.date = request.POST.get("date")
        expense.category = request.POST.get("category")
        expense.save()

        return redirect('admin_dashboard')  # Redirect to the dashboard after saving

    # Render the edit form with the current expense data if it's a GET request
    return render(request, 'admin_expense_edit.html', {'expense': expense, 'is_group': is_group})

@user_passes_test(is_superuser, login_url='admin_login')
def admin_expense_delete(request, expense_id, is_group):
    # Convert is_group to a boolean
    is_group = True if is_group.lower() == 'true' else False
    expense = get_object_or_404(IndividualExpense, id=expense_id)

    expense.delete()
    return redirect('admin_dashboard')






   

