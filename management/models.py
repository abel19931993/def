from django.contrib.auth.models import AbstractUser
from django.db import models

class SystemUser(AbstractUser):
    # Add any additional fields here
    pass
# from django.contrib.auth.models import AbstractUser
# from django.db import models

# class User(AbstractUser):
#     class Role(models.TextChoices):
#         ADMIN = "ADMIN",'Admin'
#         CREATOR = "CREATOR","Creator'
#         USER = "USER",'User'
#         DATA_INGESTER = 'DATA_INGESTER','Data_ingester'
#     base_role = Role.ADMIN

#     role = models.CharField(max_length=50, choices=Role.choices)

#     def save