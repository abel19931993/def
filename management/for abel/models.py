from django.db import models
from django.contrib.auth.models import User
from django.db.models.signals import post_save
from django.dispatch import receiver
class Role(models.Model):
    """
    Represents a role that a user can have in the system.

    Attributes:
        name (str): The name of the role (e.g., Admin, User, Manager).
        description (str): A description of the role's responsibilities.
    """
    # Defining the available roles as choices
    ROLE_CHOICES = [
        ('admin', 'Administrator'),
        ('manager', 'Manager'),
        ('editor', 'Editor'),
        ('viewer', 'Viewer'),
    
    name = models.CharField(max_length=50, choices=ROLE_CHOICES, unique=True)
    description = models.TextField(blank=True, null=True)

    def __str__(self):
        """
        Returns the string representation of the role.

        Returns:
            str: The name of the role.
        """
        return self.name

class UserProfile(models.Model):
    """
    Extends the default User model with additional information, including role.
    
    Attributes:
        user (User): The associated user.
        role (Role): The role assigned to the user.
    """
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    role = models.ForeignKey(Role, on_delete=models.SET_NULL, null=True, blank=True)

    def __str__(self):
        """
        Returns the string representation of the user profile.

        Returns:
            str: The username and role of the user.
        """
        return f"{self.user.username} - {self.role.name if self.role else 'No role assigned'}"
@receiver(post_save, sender=User)
def create_or_update_user_profile(sender, instance, created, **kwargs):
    if created:
        UserProfile.objects.create(user=instance)
    instance.userprofile.save()
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
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        """
        Returns the string representation of the resource.

        Returns:
            str: The name of the resource.
        """
        return self.name


class UserResource(models.Model):
    """
    Defines the permissions of a user on a specific resource.

    Attributes:
        user (ForeignKey): The user who is assigned permissions for the resource.
        resource (ForeignKey): The resource for which permissions are defined.
        can_create (bool): Whether the user can create the resource.
        can_view (bool): Whether the user can view the resource.
        can_edit (bool): Whether the user can edit the resource.
        can_delete (bool): Whether the user can delete the resource.
    """
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    resource = models.ForeignKey(Resource, on_delete=models.CASCADE)
    can_create = models.BooleanField(default=False)
    can_view = models.BooleanField(default=False)
    can_edit = models.BooleanField(default=False)
    can_delete = models.BooleanField(default=False)

    class Meta:
        """
        Meta class for defining constraints.
        Ensures a user can have only one unique interaction per resource.
        """
        unique_together = ('user', 'resource')

    def save(self, *args, **kwargs):
        """
        Override the save method to ensure that if a user can create a resource,
        they automatically gain permissions to edit, view, and delete the resource.
        """
        if self.can_create:
            self.can_view = True
            self.can_edit = True
            self.can_delete = True
        super().save(*args, **kwargs)

    def __str__(self):
        """
        Returns the string representation of the user-resource relationship.

        Returns:
            str: The username and resource name.
        """
        return f"{self.user.username} - {self.resource.name}"
