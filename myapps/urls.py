from django.contrib import admin
from django.urls import path
from myapps import views

urlpatterns = [
    path('', views.user_login, name='login'),
    path('register/', views.register, name='register'),
    path('index/', views.index, name='index'),
    path('admin-dashboard/', views.admin_dashboard, name='admin_dashboard'),
    path('admin-login/', views.admin_login, name='admin_login'),
    path('reset-password/', views.request_password_reset, name='reset-password'),
    path('reset-password/<uidb64>/<token>/', views.reset_password_confirm, name='reset_password_confirm'),
    path('user-logout/', views.user_logout, name='user_logout'),
    path('admin-expense/edit/<int:expense_id>/<str:is_group>/', views.admin_expense_edit, name='admin_expense_edit'),
    path('admin-expense/delete/<int:expense_id>/<str:is_group>/', views.admin_expense_delete, name='admin_expense_delete'),
    path('add_personal_expense/', views.add_personal_expense, name='add_personal_expense'),
    path('admin-logout/', views.custom_logout, name='admin_logout'),
    path('summary/', views.expense_summary, name='expense_summary'),
    path('group_summary/', views.group_summary, name='group_summary'),
    path('create_group/', views.create_group, name='create_group'),
    path('get_groups/', views.get_groups, name='get_groups'),
    path('add_group_expense/', views.add_group_expense, name='add_group_expense'),
    path('admin-user/delete/<int:user_id>/', views.admin_user_delete, name='admin_user_delete'),
]
