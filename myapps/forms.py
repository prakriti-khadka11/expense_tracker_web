from django import forms
from django.contrib.auth.models import User
from django.contrib.auth.forms import UserCreationForm
from .models import IndividualExpense

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



