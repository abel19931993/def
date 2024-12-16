from rest_framework.permissions import BasePermission

class HasRole(BasePermission):
    def has_permission(self, request , view):
        required_role = getattr(view, 'required_role',None)
        if required_role:
            return request.user.user_roles.filter(role_name=required_role)
        return super().has_permission(request, view)