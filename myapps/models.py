from django.db import models

# Create your models here.

# Model for individual expenses
class IndividualExpense(models.Model):
    name = models.CharField(max_length=255)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    date = models.DateField()
    category = models.CharField(max_length=100)

    def __str__(self):
        return f"Individual: {self.name}"
