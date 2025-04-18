"""
URL configuration for expenses_project project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.urls import path, include 

from django.contrib import admin
from django.urls import path
from myapps import views
from django.contrib.auth import views as auth_views  # Import the login view
from django.contrib import admin
from django.urls import path
from myapps import views
from django.contrib.auth import views as auth_views

from django.urls import path
from django.contrib.auth import views as auth_views

urlpatterns = [
    path('', views.user_login, name='login'),
    path('register/', views.register, name='register'),
    path('index/', views.index, name='index'),
    path('admin-dashboard/', views.admin_dashboard, name='admin_dashboard'),
    path('admin-login/', views.admin_login, name='admin_login'),
 
    path('reset-password/', views.request_password_reset, name='reset-password'),
    path('reset-password-/<uidb64>/<token>/', views.reset_password_confirm, name='reset_password_confirm'),

    path('user-logout/', views.user_logout, name='user_logout'),

    path('admin-expense/edit/<int:expense_id>/<str:is_group>/', views.admin_expense_edit, name='admin_expense_edit'),
    path('admin-expense/delete/<int:expense_id>/<str:is_group>/', views.admin_expense_delete, name='admin_expense_delete'),

    path('add_personal_expense/', views.add_personal_expense, name='add_personal_expense'),
 
]




