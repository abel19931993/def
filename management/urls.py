
from django.urls import path, include
from .views import *

from django.urls import path,re_path
from rest_framework_simplejwt import views as jwt_views


urlpatterns = [
       # url for data enrichment process
    path('police_page/',police_page, name='police_page'),
    path('search_page/',search_page, name='search_page'),
    path('create_police/',create_police, name='create_police'),
    path('create_excute/',create_excute, name='create_excute'),
    path('excute_page/',excute_page, name='excute_page'),
    path('ingestion_pipeline_page/',ingestion_pipeline_page, name ='ingestion_pipeline_page'),
    
    path('create_alices',create_alices, name='create_alices'),
    path("create_data_view",create_data_view, name='create_data_view'),
    path('data_view',data_view, name='data_view'),
    path('dashborad',dashborad, name='dashborad'),
    path('create_dashborad',create_dashborad, name='create_dashborad'),
    path("index_view",index_view, name='index_view'),
    path("create_workspace",create_workspace, name='create_workspace'),
    path('fetch_data/', fetch_from_elasticsearch, name='fetch_data'),
    path('select_index/<slug:user_indices>/', select_index, name='select_index'),
    path('display_data_stream_mapping/<slug:selectedDatabase>/',display_data_stream_mapping, name="display_data_stream_mapping"),
    # path('data_ingestion_page/',data_ingestion_page, name='data_ingestion_page'),
    path("generate_embed_link",generate_embed_link, name='generate_embed_link'),


 
       
    
]
