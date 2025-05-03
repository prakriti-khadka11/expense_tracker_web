# Create your views here.

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login
from django.contrib.auth.decorators import user_passes_test
from .models import IndividualExpense, GroupExpense
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
    if is_group:
        expense = get_object_or_404(GroupExpense, id=expense_id)
    else:
        expense = get_object_or_404(IndividualExpense, id=expense_id)

    # Handle form submission (POST request)
    if request.method == "POST":
        expense.name = request.POST.get("name")
        expense.amount = request.POST.get("amount")
        expense.date = request.POST.get("date")
        expense.category = request.POST.get("category")
          # Handle group expense members if it's a group expense
        if is_group:
            expense.member1 = request.POST.get("member1")
            expense.member2 = request.POST.get("member2")
            expense.member3 = request.POST.get("member3")
            expense.member4 = request.POST.get("member4")
            expense.member5 = request.POST.get("member5")
        expense.save()

        return redirect('admin_dashboard')  # Redirect to the dashboard after saving

    # Render the edit form with the current expense data if it's a GET request
    return render(request, 'admin_expense_edit.html', {'expense': expense, 'is_group': is_group})

@user_passes_test(is_superuser, login_url='admin_login')
def admin_expense_delete(request, expense_id, is_group):
    # Convert is_group to a boolean
    is_group = True if is_group.lower() == 'true' else False
     # Delete the expense based on whether it's individual or group
    if is_group:
        expense = get_object_or_404(GroupExpense, id=expense_id)
    else:
        expense = get_object_or_404(IndividualExpense, id=expense_id)

    expense.delete()
    return redirect('admin_dashboard')

def add_personal_expense(request):
    if request.method == "POST":
        try:
            # Parse incoming JSON data
            data = json.loads(request.body)
            print("Received data:", data)

            # Extract the fields from the incoming data
            name = data.get('name')
            amount = data.get('amount')
            date = data.get('date')
            category = data.get('category')

            # Create the personal expense in the database
            expense = IndividualExpense.objects.create(
                name=name,
                amount=amount,
                date=date,
                category=category,
            )
            expense.save()

            # Return a successful response
            return JsonResponse({'success': True, 'message': 'Personal expense added successfully!'})

        except Exception as e:
            # Log the error and return an error response
            print(f"Error: {e}")
            return JsonResponse({'success': False, 'message': 'Error adding personal expense. Please try again.'})

    return JsonResponse({'success': False, 'message': 'Invalid request method.'})

def custom_logout(request):
    """
    Logs out the currently authenticated user and redirects to the login page.

    This view function calls Django's built-in `logout` method to end the user's session.
    After logging out, the user is redirected to the login page.

    Args:
        request (HttpRequest): The HTTP request object.

    Returns:
        HttpResponseRedirect: A redirect response to the login page.
    """
    logout(request)
    return redirect('login')
   
def expense_summary(request):
    """
    Retrieves and summarizes individual expenses for a specific user and year.

    This view function expects two GET parameters:
        - user_name (str): The name of the user whose expenses should be retrieved.
        - year (int): The year for which to filter the expenses.

    The function filters expenses by the provided user and year, aggregates the total 
    amount per category, and calculates each category's percentage of the total expenses.

    Returns:
        JsonResponse: A JSON response containing:
            - 'chart_data': A dictionary with categories as keys and total expense amounts as values.
            - 'percentages': A dictionary with categories as keys and their percentage of total expenses.

    Error Responses:
        - 400 Bad Request: If the 'year' parameter is missing or not a valid integer.
        - 404 Not Found: If no expenses are found for the given user and year.
    """
    user_name = request.GET.get('user_name')
    year = request.GET.get('year')

    try:
        year = int(year)
    except (ValueError, TypeError):
        return JsonResponse({'error': 'Invalid year'}, status=400)

    expenses = IndividualExpense.objects.filter(name=user_name, date__year=year)

    if not expenses.exists():
        return JsonResponse({'error': 'No data found for the given user or year.'}, status=404)

    chart_data = {}
    total = 0
    for expense in expenses:
        chart_data[expense.category] = chart_data.get(expense.category, 0) + float(expense.amount)
        total += float(expense.amount)

    percentages = {
        category: (amount / total) * 100 for category, amount in chart_data.items()
    }

    return JsonResponse({'chart_data': chart_data, 'percentages': percentages})

