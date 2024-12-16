




























# from django.http import HttpResponseForbidden
# from functools import wraps

# def role_required(required_role):
#     """
#     Custom decorator to restrict access to views based on user roles.
#     """
#     def decorator(view_func):
#         @wraps(view_func)
#         def _wrapped_view(request, *args, **kwargs):
#             # Check if the user has the required role
#             if not request.user.is_authenticated:
#                 return HttpResponseForbidden("You are not authorized to view this page.")
            
#             user_role = request.user.role.name if hasattr(request.user, 'role') else None
#             if user_role != required_role:
#                 return HttpResponseForbidden("You do not have permission to perform this action.")
            
#             return view_func(request, *args, **kwargs)

#         return _wrapped_view
#     return decorator
# def unauthenticated_user(view_func):
#     def wrapper_func(request,*args, **kwargs):
#         if request.user.is_authenticated:
#             return redirect("index_view")
#         else:
#              return view_func(request,*args, **kwargs)
#     return wrapper_func
# # def allowed_users(allowed_roles=[]):
# #     def decorator(view_func):
# #         def wrapper_func(request,*args, **kwargs):
# #             group = None
# #             if request.user.group.exists():
# #                 group = request.users.group.all()[0].name
# #             if group in a