from django.db import models
from django.contrib.auth.models import User
# from django.db.models.signals import post_save
# from django.dispatch import receiver
class Role(models.Model):
    """
    Represents a role that a user can have in the system.

    Attributes:
        name (str): The name of the role (e.g., Admin, User, Manager).
        description (str): A description of the role's responsibilities.
    """
    ROLE_CHOICES = [
        ('admin', 'Administrator'),
        ('manager', 'Manager'),
        ('editor', 'Editor'),
        ('viewer', 'Viewer'),]
        
    
    name = models.CharField(max_length=50, choices=ROLE_CHOICES, unique=True)
    name = models.CharField(max_length=50,  unique=True)
#    

    def __str__(self):
        """
        Returns the string representation of the role.

        Returns:
            str: The name of the role.
        """
        return self.name

class UserRole(models.Model):
    """
     Extends the default User model with additional information, including role.
    
     Attributes:
         user (User): The associated user.
         role (Role): The role assigned to the user.
     """
    user = models.ForeignKey(User,on_delete=models.CASCADE,related_name='user_roles')
    role = models.ForeignKey(Role,on_delete=models.CASCADE)
    class Meta:
        unique_together=("user","role")
class Resource(models.Model):
    """
    Represents a resource that a user can interact with, such as a document or project.

    Attributes:
        name (str): The name of the resource (e.g., Document 1, Project A).
        description (str): A description of the resource.
        created_at (datetime): Timestamp of when the resource was created. 
        updated_at (datetime): Timestamp of when the resource was last updated.
    """
    
    workspace_name = models.CharField(max_length=100)
    index_name = models.TextField(blank=True, null=True)
    data_view_id = models.TextField(blank=True, null=True)
    alias_id = models.TextField(blank=True, null=True)
    dashboard_id = models.TextField(blank=True, null=True)
    created_by = models.ForeignKey(User,on_delete=models.CASCADE,related_name='created_by')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    def __str__(self):
        """
        Returns the string representation of the resource.

        Returns:
            str: The name of the resource.
        """
        return self.workspace_name