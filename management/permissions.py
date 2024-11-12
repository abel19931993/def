from rest_framework import permissions

from .models import *


class IsAllower(permissions.BasePermission):
    def has_permission(self, request, view):
        return (
            request.user.is_authenticated
            and request.user.user_role.role_name == "allower"
        )

class IsOperator(permissions.BasePermission):
    def has_permission(self, request, view):
        return (
            request.user.is_authenticated
            and request.user.user_role.role_name == "operator"
        )
class IsRequester(permissions.BasePermission):
    def has_permission(self, request, view):
        return (
            request.user.is_authenticated
            and request.user.user_role.role_name == "requester"
        )

class IsAdmin(permissions.BasePermission):
    def has_permission(self, request, view):
        return (
            request.user.is_authenticated
            and request.user.user_role.role_name == "admin"
        )
