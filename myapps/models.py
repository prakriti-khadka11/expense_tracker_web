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

class Member(models.Model):
    name = models.CharField(max_length=255)

    def __str__(self):
        return self.name

class GroupExpense(models.Model):
    name = models.CharField(max_length=200)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    date = models.DateField()
    category = models.CharField(max_length=100)
    is_group = models.BooleanField(default=True)

    # Many-to-Many Relationship with Members
    members = models.ManyToManyField(Member, related_name="group_expenses")

    def __str__(self):
        return self.name