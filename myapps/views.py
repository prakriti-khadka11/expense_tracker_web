from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import user_passes_test
from .models import IndividualExpense, GroupExpense, Group, Member
from django.http import JsonResponse, HttpResponseBadRequest
import json
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.contrib import messages
from .forms import UserRegisterForm
from django.core.mail import EmailMessage
from django.contrib.sites.shortcuts import get_current_site
from django.utils.encoding import force_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.template.loader import render_to_string
from django.urls import reverse
from .utils import account_activation_token
import logging

# Configure logging
logger = logging.getLogger(__name__)

def register(request):
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

def admin_login(request):
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
    return user.is_authenticated and user.is_superuser

@user_passes_test(is_superuser, login_url='admin_login')
def admin_dashboard(request):
    personal_expenses = IndividualExpense.objects.all()
    group_expenses = GroupExpense.objects.all()
    users = User.objects.all()
    logger.info(f"Admin dashboard accessed. Found {personal_expenses.count()} personal expenses and {group_expenses.count()} group expenses.")
    context = {
        'personal_expenses': personal_expenses,
        'group_expenses': group_expenses,
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
            reset_url = 'http://' + current_site.domain + link
            email_subject = 'Reset Your Password'
            email_message = EmailMessage(
                email_subject,
                'Hi ' + user.username + ', Click the link below to reset your password of your Expense Tracker Website: \n' + reset_url,
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
                if new_password != confirm_password:
                    messages.error(request, "The passwords do not match. Please try again.")
                    return render(request, 'reset-password-confirm.html', {'validlink': True})
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
    logout(request)
    return redirect('login')

@user_passes_test(is_superuser, login_url='admin_login')
def admin_expense_edit(request, expense_id, is_group):
    if is_group:
        expense = get_object_or_404(GroupExpense, id=expense_id)
    else:
        expense = get_object_or_404(IndividualExpense, id=expense_id)
    if request.method == "POST":
        expense.name = request.POST.get("name")
        expense.amount = request.POST.get("amount")
        expense.date = request.POST.get("date")
        expense.category = request.POST.get("category")
        if is_group:
            expense.members.clear()
            member_names = [
                request.POST.get(f"member{i}") for i in range(1, 6) if request.POST.get(f"member{i}")
            ]
            for name in member_names:
                member, _ = Member.objects.get_or_create(name=name)
                expense.members.add(member)
        expense.save()
        return redirect('admin_dashboard')
    return render(request, 'admin_expense_edit.html', {'expense': expense, 'is_group': is_group})

@user_passes_test(is_superuser, login_url='admin_login')
def admin_expense_delete(request, expense_id, is_group):
    is_group = is_group.lower() == 'true'
    if is_group:
        expense = get_object_or_404(GroupExpense, id=expense_id)
    else:
        expense = get_object_or_404(IndividualExpense, id=expense_id)
    expense.delete()
    return redirect('admin_dashboard')

def add_personal_expense(request):
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            expense = IndividualExpense.objects.create(
                name=data.get('name'),
                amount=data.get('amount'),
                date=data.get('date'),
                category=data.get('category'),
            )
            expense.save()
            logger.info(f"Personal expense '{expense.name}' added: Rs.{expense.amount}, {expense.date}, {expense.category}")
            return JsonResponse({'success': True, 'message': 'Personal expense added successfully!'})
        except Exception as e:
            logger.error(f"Error adding personal expense: {str(e)}")
            return JsonResponse({'success': False, 'message': f'Error adding personal expense: {str(e)}'})
    return JsonResponse({'success': False, 'message': 'Invalid request method.'})

def custom_logout(request):
    logout(request)
    return redirect('login')

def expense_summary(request):
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
    percentages = {category: (amount / total) * 100 for category, amount in chart_data.items()}
    return JsonResponse({'chart_data': chart_data, 'percentages': percentages})

def group_summary(request):
    username = request.GET.get('username')
    year = request.GET.get('year')
    group_name = request.GET.get('group_name')
    expense_name = request.GET.get('expense_name')
    
    try:
        year = int(year)
    except (ValueError, TypeError):
        return JsonResponse({'error': 'Invalid year'}, status=400)
    
    try:
        member = Member.objects.get(name=username)
    except Member.DoesNotExist:
        return JsonResponse({'error': 'User not found in any groups.'}, status=404)
    
    # Start with base query
    expenses = GroupExpense.objects.filter(members=member, date__year=year)
    
    # Apply filters if provided
    if group_name:
        expenses = expenses.filter(group__name__iexact=group_name)
    if expense_name:
        expenses = expenses.filter(name__iexact=expense_name)
    
    if not expenses.exists():
        return JsonResponse({'error': 'No group expenses found for the given criteria.'}, status=404)
    
    chart_data = {}
    total = 0
    for expense in expenses:
        member_count = expense.members.count()
        if member_count > 0:
            split_amount = float(expense.amount) / member_count
            chart_data[expense.category] = chart_data.get(expense.category, 0) + split_amount
            total += split_amount
    
    if total == 0:
        return JsonResponse({'error': 'No group expenses found for the given criteria.'}, status=404)
    
    percentages = {category: (amount / total) * 100 for category, amount in chart_data.items()}
    return JsonResponse({'chart_data': chart_data, 'percentages': percentages})

def create_group(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            group_name = data.get('name')
            member_names = data.get('members', [])
            if not group_name:
                return JsonResponse({'success': False, 'message': 'Group name is required'}, status=400)
            if not member_names:
                return JsonResponse({'success': False, 'message': 'At least one member is required'}, status=400)
            if request.user.is_authenticated and request.user.username not in member_names:
                member_names.append(request.user.username)
            group = Group.objects.create(name=group_name)
            for name in member_names:
                member, _ = Member.objects.get_or_create(name=name)
                group.members.add(member)
            logger.info(f"Group '{group.name}' created with members: {', '.join(member_names)}")
            return JsonResponse({'success': True, 'message': 'Group created successfully', 'group_id': group.id})
        except json.JSONDecodeError:
            logger.error("Invalid JSON data in create_group")
            return JsonResponse({'success': False, 'message': 'Invalid JSON data'}, status=400)
        except Exception as e:
            logger.error(f"Error creating group: {str(e)}")
            return JsonResponse({'success': False, 'message': f'Error: {str(e)}'}, status=400)
    return JsonResponse({'success': False, 'message': 'Invalid request method'}, status=405)

def get_groups(request):
    if request.method == 'GET':
        groups = Group.objects.all()
        group_data = [{'id': group.id, 'name': group.name} for group in groups]
        logger.info(f"Fetched {len(group_data)} groups")
        return JsonResponse({'success': True, 'groups': group_data})
    return JsonResponse({'success': False, 'message': 'Invalid request method'}, status=405)

def add_group_expense(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            group_id = data.get('group_id')
            name = data.get('name')
            amount = data.get('amount')
            date = data.get('date')
            category = data.get('category')
            if not all([group_id, name, amount, date, category]):
                logger.error("Missing required fields in add_group_expense")
                return JsonResponse({'success': False, 'message': 'All fields are required'}, status=400)
            group = get_object_or_404(Group, id=group_id)
            member_count = group.members.count()
            if member_count == 0:
                logger.error(f"Group '{group.name}' has no members")
                return JsonResponse({'success': False, 'message': 'Group has no members'}, status=400)
            split_amount = float(amount) / member_count
            expense = GroupExpense.objects.create(
                name=name,
                amount=amount,
                date=date,
                category=category,
                is_group=True,
                group=group
            )
            for member in group.members.all():
                expense.members.add(member)
            expense.save()
            logger.info(f"Group expense '{name}' added to '{group.name}': Rs.{amount}, {date}, {category}, Members: {', '.join([m.name for m in group.members.all()])}")
            return JsonResponse({
                'success': True,
                'message': f'Expense added to {group.name} and split successfully!',
                'split_amount': split_amount
            })
        except json.JSONDecodeError:
            logger.error("Invalid JSON data in add_group_expense")
            return JsonResponse({'success': False, 'message': 'Invalid JSON data'}, status=400)
        except Exception as e:
            logger.error(f"Error adding group expense: {str(e)}")
            return JsonResponse({'success': False, 'message': f'Error: {str(e)}'}, status=400)
    return JsonResponse({'success': False, 'message': 'Invalid request method'}, status=405)