from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils import timezone
from datetime import datetime
from django.db.models import Q,JSONField
from django.core.exceptions import ValidationError
from django.core.validators import MinLengthValidator

from django.contrib.auth.models import (
    AbstractBaseUser,
    BaseUserManager,
    PermissionsMixin,
)

# Create your models here.

class SystemUserManager(BaseUserManager):
    def create_user(self, email, username, password=None, **extra_fields):
        if not email:
            raise ValueError("The Email field must be set")
        email = self.normalize_email(email)
        user = self.model(email=email, username=username, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, username, password=None, **extra_fields):
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", False)

        return self.create_user(email, username, password, **extra_fields)

class UserRoles(models.Model):
    role_name = models.CharField(max_length=200)

class SystemUser(AbstractBaseUser, PermissionsMixin):
    ROLE_CHOICES = (
        ("Director", "Director"),
        ("Department", "Department"),
        ("Officer", "Officer"),
    )
   
    email = models.EmailField(unique=True)
    username = models.CharField(max_length=30, unique=True)
    first_name = models.CharField(max_length=30, default="")
    last_name = models.CharField(max_length=30, default="")
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=True)
    # Add your custom fields here
    user_role = models.CharField(UserRoles, choices=ROLE_CHOICES,max_length=15)
    
    profile_picture = models.ImageField(
        upload_to="profile_pictures/", null=True, blank=True
    )
    age = models.IntegerField(default=0)
    gender = models.CharField(max_length=7)
    address = models.CharField(max_length=7)
    objects = SystemUserManager()

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["username"]

    def __str__(self):
        return self.email

class Target(models.Model):
    photo = models.ImageField(
        upload_to="profile_pictures/", null=True, blank=True
    )
    name = models.JSONField(blank = True)
    target_location = models.JSONField()
    phone = models.JSONField()
    imei = models.JSONField()
    def __str__(self):
        return self.status
    
class Case(models.Model):
    case_name = models.CharField(max_length=100,unique=True,name="የስጋት አይነት")

class subCase(models.Model):
    case_name = models.ForeignKey(Case, on_delete=models.CASCADE, related_name="Case_Type")
    sub_case = models.CharField(max_length=100,name="Case")
   
class First_request(models.Model):
    target_code = models.ForeignKey(Target, related_name="Operation_Reqiest", on_delete=models.CASCADE, blank=True,null=True)
    name = models.JSONField()
    phone_number = models.JSONField()
    case = models.ForeignKey(to=Case, on_delete=models.CASCADE, blank=True, null=True)
    subcase = models.ForeignKey(to=subCase, on_delete=models.CASCADE, blank=True, null=True)
    photo = models.ImageField(
        upload_to="file_pictures/", null=True, blank=True
    )    
    target_location = models.CharField(max_length=200, blank = True)
    status = models.CharField(max_length=10, default='pending')
    description = models.CharField(max_length=200, blank = True)
    request_submited_date = models.DateTimeField(auto_now=True, auto_now_add=False)
    request_submited_entity = models.CharField(max_length=50,help_text="የኦፕሬሽን ጥያቄ ያቀረበው ተቋም")
    request_subited_person = models.ForeignKey(SystemUser, related_name="A_person_Who_request_operation_to_be_condacted", on_delete=models.CASCADE)
    
    def __str__(self):
        return self.status

class OperationResult(models.Model):
    Request_code = models.ForeignKey(First_request, related_name="Report_for_Request_Submited",on_delete=models.CASCADE)
    
    result_list = models.JSONField(default=list)
    end_date = models.DateTimeField()
    house_number = models.IntegerField(null=True, blank=True)

    name = models.CharField(max_length=400,null=True, blank=True)
    target_location = models.CharField(max_length=400,null=True, blank=True)
    phone_number =  models.JSONField(default=list)
    
    car_info = models.JSONField(default=list)
    description = models.CharField(max_length=400)
    profile_picture = models.ImageField(
        upload_to="target_profile/"
    )
    target_provider_person = models.CharField(max_length=100)
    target_accepter_company = models.CharField(max_length=100)
    target_provider_company = models.CharField(max_length=100)
    target_accepter_person = models.CharField(max_length=100)

class Unit(models.Model):
    unit_name = models.CharField(max_length=50,unique=True)

class Assign(models.Model):
    allower = models.ForeignKey(SystemUser, related_name="A_person_who_allow_the_operation" , on_delete=models.CASCADE)
    assigned_Operator = models.ForeignKey(SystemUser, related_name="A_person_who_assing_to_work_on_the_operation", on_delete=models.CASCADE)
    request_code = models.ForeignKey(First_request, related_name="Request_operation", on_delete=models.CASCADE)

