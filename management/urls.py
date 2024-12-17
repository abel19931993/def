
from django.urls import path, include
from .views import *

from django.urls import path,re_path
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)


urlpatterns = [
    path('api/auth/register',RegisterView.as_view(),name="auth_register"),
    # path('api/auth/login',LoginView.as_view(),name="auth_login"),
    path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('api/workspace/',WorkspaceListCreateView.as_view(),name='workspace_list_create'),
    path('list_user_workspaces/',list_user_workspaces,name='list_user_workspaces'),
    path('list_user_workspacesss/<int:workspace_id>/', list_user_workspacesss, name='list_user_workspacesss'),
    path('viewdashboard/', viewdashboard, name='viewdashboard'),
    # path('manage_workspace_page', manage_workspace_page, name='manage_workspace_page'),
    path('login', login_view, name='login'),
    path('loginPage', loginPage, name='loginPage'),
    path('logout_view', logout_view, name='logout_view'),
    # path('register_func', register_func, name='registerPage'),
    path('create_alices',create_alices, name='create_alices'),
    path("create_data_view",create_data_view, name='create_data_view'),
    path('data_view',data_view, name='data_view'),
    path('dashborad',dashborad, name='dashborad'),
    path('create_dashborad',create_dashborad, name='create_dashborad'),
    path("index_view",index_view, name='index_view'),
    path("create_workspace",create_workspace, name='create_workspace'),
    path('fetch_data/', fetch_from_elasticsearch, name='fetch_data'),
    path('select_index/<slug:user_indices>/',select_index, name="select_index"),
    path('display_data_stream_mapping/<slug:selectedDatabase>/',display_data_stream_mapping, name="display_data_stream_mapping"),
    path("generate_embed_link",generate_embed_link, name='generate_embed_link'),
    path("search", standard_search, name="search"),
    # path("search_result",search_result,name="search_result")
# update_alias--------------------------------
    
    path('update_alias_page',update_alias_page, name='update_alias_page'),
    # path('select_alias/', select_alias, name="select_alias"),
    path('select_alias/<slug:user_alias>/',select_alias, name="select_alias"),
    path('update_alias__',update_alias__, name='update_alias__'), 
    path('search_alias__',search_alias__, name='search_alias__'),
    path('welcome__dani',welcome__dani, name='welcome__dani'),
]
