
from django.urls import path, include
from .views import *

from django.urls import path,re_path
from rest_framework_simplejwt import views as jwt_views


urlpatterns = [
 
    path('create_alices',create_alices, name='create_alices'),
    # path('data_stream',data_stream, name='data_stream'),
    path("create_data_view",create_data_view, name='create_data_view'),
    path('data_view',data_view, name='data_view'),
    path('dashborad',dashborad, name='dashborad'),
    path('create_dashborad',create_dashborad, name='create_dashborad'),
    path("index_view",index_view, name='index_view'),
    path("create_workspace",create_workspace, name='create_workspace'),
    path('select_index/<slug:user_indices>/',select_index, name="select_index"),
    path('display_data_stream_mapping/<slug:selectedDatabase>/',display_data_stream_mapping, name="display_data_stream_mapping"),
    # path('data_ingestion_page/',data_ingestion_page, name='data_ingestion_page'),
    path("generate_embed_link",generate_embed_link, name='generate_embed_link'),
       
    
]
