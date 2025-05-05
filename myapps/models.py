from django.db import models

# Model for individual expenses
class IndividualExpense(models.Model):
    name = models.CharField(max_length=255)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    date = models.DateField()
    category = models.CharField(max_length=100)

    def __str__(self):
        return f"Individual: {self.name}"

# Model for group members
class Member(models.Model):
    name = models.CharField(max_length=255, unique=True)

    def __str__(self):
        return self.name

# Model for group expenses
class GroupExpense(models.Model):
    name = models.CharField(max_length=200)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    date = models.DateField()
    category = models.CharField(max_length=100)
    is_group = models.BooleanField(default=True)
    members = models.ManyToManyField(Member, related_name="group_expenses")
    group = models.ForeignKey('Group', on_delete=models.CASCADE, related_name="expenses", null=True)

    def __str__(self):
        return self.name

# Model for groups
class Group(models.Model):
    name = models.CharField(max_length=100, unique=True)
    members = models.ManyToManyField(Member, related_name="groups")
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name