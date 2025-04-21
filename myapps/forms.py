from django import forms
from django.contrib.auth.models import User
from django.contrib.auth.forms import UserCreationForm
from .models import IndividualExpense, GroupExpense, Member

class UserRegisterForm(UserCreationForm): 
    email = forms.EmailField(required=True)

    class Meta:
        model = User
        fields = ['username', 'email', 'password1', 'password2'] 

    def save(self, commit=True):
        user = super().save(commit=False)
        user.email = self.cleaned_data['email'] 
        if commit:
            user.save()
        return user

# Form for Individual Expenses
class IndividualExpenseForm(forms.ModelForm):
    class Meta:
        model = IndividualExpense
        fields = ['name', 'amount', 'date', 'category']
        widgets = {
            'date': forms.DateInput(attrs={'type': 'date'}),
        }

# Form for Group Expenses
class GroupExpenseForm(forms.ModelForm):
    members = forms.ModelMultipleChoiceField(
        queryset=Member.objects.all(),  # Allow selection of multiple members
        widget=forms.CheckboxSelectMultiple,  # Use checkboxes
        required=False  # Optional field
    )

    class Meta:
        model = GroupExpense
        fields = ['name', 'amount', 'date', 'category', 'members']
        widgets = {
            'date': forms.DateInput(attrs={'type': 'date'}),
        }


