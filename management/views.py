import requests
import json,copy
import time
from datetime import datetime
import csv
from django.contrib.auth.models import Permission
from django.conf import settings
from django.http import HttpResponse, JsonResponse
import os
from django.core.files.storage import FileSystemStorage
from .serializers import *
from .permissions import *
from .models import *
from django.shortcuts import render,redirect,get_object_or_404
from .serializers import *
import uuid
from elasticsearch import Elasticsearch
from requests.exceptions import RequestException
from typing import Dict
import elasticsearch.exceptions as ElasticsearchException
from django.core.paginator import Paginator

import pprint
from requests.exceptions import RequestException
from django.contrib import messages
from django.contrib.auth import authenticate,login,logout
from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import csrf_protect

from rest_framework import generics
from rest_framework.permissions import AllowAny,IsAuthenticated
from rest_framework import status 
from django.contrib.auth.models import User
from .serializers import RegisterSerializer,ResourceSerializer,LoginSerializer
from rest_framework.response import Response
from rest_framework.decorators import api_view, permission_classes
from rest_framework_simplejwt.tokens import RefreshToken
# def getlanguges(request):
    
#     token=request.session.get('auth_token')
#     print("SUCCESS",token)

#     Token=f"Token {token}"
#     headers = {
#     "Authorization": Token,
#     "Content-Type": "application/json",
#      }
#     api_response = requests.get(f"{url}/language_public/",headers=headers).json()
#     languages = api_response.get("data", [])
    
#     return [{"code": lang["language_code"], "name": lang["language_name"]}
#                            for lang in languages]
#                            headers = {
#     'Content-Type': 'application/json',
#     'kbn-xsrf': 'true'  # Required header for Kibana API requests
# }

workspace_name = None  
alias_name = None
data_view_id = None
dashboard_ids = None
work_type = None
auth_token = None
class RegisterView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class  = RegisterSerializer
from django.contrib.auth import authenticate
from rest_framework.response import Response
from rest_framework.decorators import api_view
from rest_framework_simplejwt.tokens import RefreshToken
from django.shortcuts import render, redirect
from django.contrib import messages
from .serializers import UserSerializer

# @api_view(['POST'])
def login_view(request):
    username = request.POST.get('username')
    password = request.POST.get('password')
    print(username)
    user = authenticate(username=username, password=password)
    if user is not None:
            refresh = RefreshToken.for_user(user)
            user_serializer = UserSerializer(user)
            request.session['auth_token'] = str(refresh.access_token)
            print(str(refresh.access_token))
            login(request, user)
            return redirect('list_user_workspaces')
            
    return redirect('loginPage')
def loginPage(request):
    tabss = [
            {"id": "Content"}
            ]
    context = {
            'tabs':  tabss
            # Add more context variables as neededS
            }
    return render(request,'login.html',context)

def logout_view(request):
    logout(request)
    request.session.clear()
    messages.success(request, "You have been logged out successfully and all sessions have been cleared.")
    return redirect('loginPage')

class WorkspaceListCreateView(generics.ListCreateAPIView):
    queryset = Resource.objects.all()
    serializer_class = ResourceSerializer
    permission_classes = [IsAuthenticated]
    
    def perform_create(self,serializer):
        serializer.save(created_by=self.request.user)
def list_user_workspaces(request):
    resource_serializer_responce = ResourceSerializer(Resource.objects.filter(created_by__id = request.user.id), many=True)
    data = resource_serializer_responce.data
    print(request.user)
    recent_workspaces = {'recent_workspaces':data}
    return render(request,'welcome_page.html',context = recent_workspaces)
def list_user_workspacesss(request, workspace_id):
    resource = get_object_or_404(Resource, id=workspace_id)
    resource_serializer_responce = ResourceSerializer(resource)
    data = resource_serializer_responce.data
    request.session['dashboard_ids'] = data['dashboard_id']
    
    print("abellllllll")
    context = {
            'workspace':  data
            # Add more context variables as neededS
            }
    
    return render(request, 'manage_workspace_page.html',context)

    




class WorkspaceDetailView(generics.RetrieveUpdateDestroyAPIView):

    queryset = Resource.objects.all()
    serializer_class = ResourceSerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        return Resource.objects.filter(created_by=self.request.user)




headers = {
        'Content-Type': 'application/json',
          # Example of including an authorization header if needed
    }
def list_user_indices():
    try:
        endpoint = f"{settings.ES_HOST}/_cat/indices?v&h=index&format=json"
        response = requests.get(endpoint, headers=headers,timeout=10)
        response.raise_for_status()
        all_indices = response.json()
        user_indices = [index['index'] for index in all_indices if not index['index'].startswith('.')]
        return user_indices
    except RequestException as e:
        print(f"Error fetching user indices: {e}")
        return []

def get_data_views(auth=None):
    """
    Get all data views from Kibana.
    """
    endpoint = f"{settings.KIBANA_HOST}/api/data_views"
    try:
        response = requests.get(endpoint, headers=headers, auth=auth, timeout=10)
        response.raise_for_status()
        data_views = response.json().get('data_view', [])
        data_views_info = []
        for data_view in data_views:
            view_info = {
                'name': data_view.get('name'),
                'id': data_view.get('id'),
                'indices': data_view.get('title')
            }
            if not view_info['name'].startswith('.'):
                data_views_info.append(view_info)
        print("Retrieved data views info successfully.")
        return data_views_info
    except RequestException as e:
        print(f"Failed to retrieve data views: {e}")
        return None
    
def get_data_stream_names():
    try:
        response = requests.get(settings.ES_HOST+'/_data_stream', timeout=10)
        response.raise_for_status()
        all_data_streams = response.json()
        data_stream_names = [
            ds['name'] for ds in all_data_streams['data_streams'] 
            if not ds.get('system', False)
        ]
        print(data_stream_names)
        return data_stream_names
    except RequestException as e:
        print(f"Error fetching data stream names: {e}")
        return []
# Example usage
template_dashboard_id = "your_template_dashboard_id"  # Replace with the actual template dashboard ID
new_dashboard_title = "My New Dashboard"
new_data_view_id = "your_new_data_view_id"  # Replace with the actual data view ID
auth = ('username', 'password')
def create_workspace(request):
    global workspace_name
    if request.method == 'POST':
        workspace_name = request.POST.get('workspace_name')
        work_type = request.POST.get('work_type')
        print(work_type)
        request.session['workspace_name'] = workspace_name
        request.session['work_type'] = work_type  # Store in session
        time.sleep(1)
        print(f'Workspace Name: {workspace_name}')  # For debugging purposes
    if work_type == 'index':
            # Call the list_user_indices() function to get the supported databases for Indic
            supported_database = list_user_indices()
            print(supported_database)
            # Pass the data to the filter.html template
            return render(request, 'filter.html', context={
                'supported_database': supported_database,
                'workspace_name': workspace_name
            })
    elif work_type == 'datastream':
            # Call the get_data_stream_names() function to get the supported databases for Datastream
            supported_database = get_data_stream_names()
            # Pass the data to the data_stream.html template
            return render(request, 'data_stream.html', context={
                'supported_database': supported_database,
                'workspace_name': workspace_name
            })

    else:
            # If the work_type is invalid (not 'indic' or 'datastream')
        return HttpResponse("Invalid work type", status=400)
    # return render(request, 'filter.html', context={
    #     'supported_database': list_user_indices(),
    #     'workspace_name': workspace_name  # Pass the workspace name to the template
    # })
# a
# @allowed_users(allowed_roles=["viewer"])
def index_view(request):
    tabss = [
    {"id": "Content for Tab 3"}
]
    context = {
            'tabs':  tabss
            # Add more context variables as neededS
            }
    return render(request,'index.html',context)

# Step 3: Select index
def select_index(request, user_indices):
    try:
        endpoint = f"{settings.ES_HOST}/{user_indices}/_mapping"
        print(type(endpoint))
        response = requests.get(endpoint, headers=headers,timeout=10)
        print(response)
        if response.status_code == 200:
            mapping = response.json()
            index_mapping = mapping.get(user_indices, {})
            properties = index_mapping.get('mappings', {}).get('properties', {})

            print(f"Fields and Types in Index '{user_indices}':")
            known_fields = []  

            def traverse_fields(fields, parent_field=""):
                for field, attributes in fields.items():
                    full_field_name = f"{parent_field}.{field}" if parent_field else field
                    field_type = attributes.get('type', 'object')

                    if field_type != 'object':
                        known_fields.append(full_field_name)

                    if field_type == 'object' and 'properties' in attributes:
                        traverse_fields(attributes['properties'], full_field_name)

            if properties:
                traverse_fields(properties)
              
                if known_fields:
                    return JsonResponse({'columns': known_fields})
                    for field, field_type in known_fields:
                        print(f"- {field}: {field_type}")
                else:
                    print("No fields with known types found in the selected index.")
            else:
                print("No fields found in the selected index.")
        else:
            print(f"Failed to retrieve mappings for index '{user_indices}'. HTTP Status Code: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"An error occurred while fetching the mappings: {e}")

def input_filter_values(input_data, is_csv=True):
    filters_map = {}
    
    if is_csv:
        if input_data:
            try:
                with open(input_data, newline='') as csvfile:
                    reader = csv.reader(csvfile)
                    headers = next(reader)  # Get the first row as headers
                    for row in reader:
                        if row:  # Check if the row is not empty
                            for i, value in enumerate(row):
                                field = headers[i] if i < len(headers) else f"field_{i}"
                                if field in filters_map:
                                    filters_map[field].append(value)
                                else:
                                    filters_map[field] = [value]  # Create a new list for the field
            except FileNotFoundError:
                print(f"Error: The file at {input_data} was not found.")
                return {}
        else:
            print("Error: No input data provided for CSV.")
    else:
        print("inputttttttttttttttt")
        print(input_data)
        for field_name, value in input_data:
            value_list = [v.strip() for v in value.split(',')] 
            if field_name in filters_map:
                filters_map[field_name].append(value_list)
            else:
                filters_map[field_name] = value_list
        

    return filters_map
supported_datebase = ['postgresql','mysql']   

def create_filter_body(filter_list, field):
    """
    Iterate over filter_list items, then Check if the filter_field is in field and Add terms filters.

    Parameter: 
    - filter_list: A dictionary mapping fields to their filter values.
    - field: Selected fields.

    Returns:
    - filter_should: Create terms query with the matched field and values.

    """
    filter_should = []
    
    for filter_field, values in filter_list.items():
        # Check if the filter_field exists directly in the field list
        if filter_field in field:
            if values:
                for value in values:
                    if value and value.strip():
                        filter_should.append(
                            {
                                "terms": {
                                    filter_field: [value]
                                }
                            }
                        )
            else:
                print(f"Skipping {filter_field} due to empty values.")
        else:
            # Check for nested fields (e.g., common.sample.field)
            for existing_field in field:
                if filter_field in existing_field:
                    if values:
                        for value in values:
                            if value and value.strip():
                                filter_should.append(
                                    {
                                        "terms": {
                                            existing_field: [value]
                                        }
                                    }
                                )
                    else:
                        print(f"Skipping {existing_field} due to empty values.")
                    break
            else:
                print(f"{filter_field} does not exist in the provided field list or as a sub-field.")   
    return filter_should          
        
def create_alias(selected_index,filter_body, workspace_name,request):
    global alias_name
    """
    Create aliases on elastic search

    Parameter: 
    - selected_index: index name
    - filter_body: Created terms query
    - workspace_name: name of created work space
    """
    if filter_body:
        current_timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        alias_name = f"{workspace_name}_{current_timestamp}"
        print(alias_name)
        body = {
            "actions": [
                {
                    "add": {
                        "index": selected_index,
                        "alias": alias_name,
                        "filter": {
                            "bool": {
                                "should": filter_body
                            }
                        }
                    }
                }
            ]
        }

        response = requests.post(settings.ES_HOST+'/_aliases', json=body)
        if response.status_code == 200:
            print(f"Alias {alias_name} created successfully with filter list!")
            request.session['alias_name'] = alias_name  # Store in session
            time.sleep(1)
        else:
            print(f"Failed to create alias. HTTP Status Code: {response.status_code}")
    else:
        print("No filter values provided. Alias creation aborted.")
filters = {}
filter_body =[]
result =[]
def create_alices(request):
    
    if request.method == 'POST':
        # Convert items to a list
        post_items = list(request.POST.items())

        # Exclude the last element and get items after the 4th
        filtered_items = post_items[4:-1]  # Start from the 5th item and exclude the last

        # Create a list or dictionary with the results
        result = [(field_name, value) for field_name, value in filtered_items]

    
    workspace_name = request.POST.get('workspace_name')
    columns = request.POST.getlist('columns[]')
    # manual_fields = request.POST.getlist('manual_fields[]')  # Remove brackets
    index_name = request.POST.get('database_type')

    csv_file = request.FILES.get('csv_file') 
    
    if csv_file:
        fs = FileSystemStorage()
        filename = fs.save(csv_file.name, csv_file)
        csv_file_path = os.path.join(settings.MEDIA_ROOT, filename)
        filters =input_filter_values(csv_file_path, is_csv=True)
        filter_body = create_filter_body(filters,columns)
    else:
       
        filters = input_filter_values(result, is_csv=False)
        filter_body = create_filter_body(filters,columns)
   
    
    create_alias(index_name, filter_body, workspace_name,request) 
    return redirect("data_view")

def get_date_fields_for_alias(request, specific_alias):
    work_type = request.session.get('work_type', None)
    es = Elasticsearch([settings.ES_HOST])

    try:
        response = es.indices.get_alias()
        alias_found = False
        date_fields = {}
        
        for index, data in response.items():
            if specific_alias in data['aliases']:
                alias_found = True
                field_response = es.indices.get_mapping(index=index)
                fields = field_response[index]['mappings']['properties']
                
                if work_type == 'datastream':
                    ds_response = requests.get(f'settings.ES_HOST/_data_stream/{index}', timeout=10)
                    ds_response.raise_for_status()
                    data_stream_info = ds_response.json()
                    backing_indices = data_stream_info['data_streams'][0].get('indices', [])
                    latest_index_name = backing_indices[-1]['index_name']
                    fields = field_response[latest_index_name]['mappings']['properties']
                
                date_fields = {field_name: field_info for field_name, field_info in fields.items() if field_info.get('type') == 'date'}
        
        if alias_found:
            return {specific_alias: list(date_fields.keys())}
        else:
            print(f"Alias '{specific_alias}' not found.")
            return None
    except (ElasticsearchException, RequestException) as e:
        print(f"Error retrieving date fields for alias '{specific_alias}': {e}")
        return None

            
    except Exception as e:
        print(f"Error retrieving date fields for alias '{specific_alias}': {e}")
        return None
# es = Elasticsearch([{'host': '192.168.6.175', 'port': 9200, 'scheme': 'http'}])
def fetch_from_elasticsearch(request):
    alias_name = request.session.get('alias_name', None)
    print(f"Fetching data from Elasticsearch for alias: {alias_name}")
    
    query = {
        "_source": ["From", "location", "imsi", "To", "duration", "City_name"],
        "query": {"match_all": {}},
        "size": 10000
    }
    try:
        response = settings.ES.search(index=alias_name, body=query)
        result = [hit['_source'] for hit in response['hits']['hits']]
        return JsonResponse(result, safe=False)
    except ElasticsearchException as e:
        error_message = {"error": str(e)}
        return JsonResponse(error_message, status=500)

def create_data_view_(data_view_index_pattern, time_field_name, data_view_name,request):
    """
    Create a new data view in Kibana.
    """
    data_view_payload = {
        "data_view": {
            'name': data_view_name,
            "title": data_view_index_pattern,
            "timeFieldName": time_field_name,
            "allowNoIndex": False,
        }
    }
    endpoint = f"{settings.KIBANA_HOST}/api/data_views/data_view"
    try:
        response = requests.post(endpoint, headers=headers, data=json.dumps(data_view_payload), auth=auth, timeout=10)
        response.raise_for_status()
        data_view = response.json().get('data_view', [])
        request.session['data_view_id'] = data_view.get('id')
        print("Data view created successfully.")
        return response.json()
    except RequestException as e:
        print(f"Failed to create data view: {e}")
        return None

def get_data_views(auth=None):
    """
    Get all data views from Kibana.

    :param settings.KIBANA_HOST: The base URL for the Kibana instance (e.g., "http://localhost:5601").
    :param auth: Optional tuple (username, password) for Basic Authentication.
    :return: List of data views or None if the request fails.
    """
    
    # Construct the API endpoint for getting data views
    endpoint = f"{settings.KIBANA_HOST}/api/data_views"

    # Make the GET request to retrieve all data views
    response = requests.get(endpoint, headers=headers)

    if response.status_code == 200:
        data_views = response.json().get('data_view', [])
        data_views_info = []
        for data_view in data_views:
            # Extract the required fields: name, id, and indices
            view_info = {
                'name': data_view.get('name'),
                'id': data_view.get('id'),
                'indices': data_view.get('title')  # Assuming title represents the index pattern
            }
            if not view_info['name'].startswith('.'):
             data_views_info.append(view_info)

        print("Retrieved data views info successfully.")
        return data_views_info
    else:
        print(f"Failed to retrieve data views: {response.status_code} - {response.text}")
        return None



def data_view(request):
    
    alias_name = request.session.get('alias_name', None)  # Retrieve from session
    indexData = get_date_fields_for_alias(request,alias_name)
    print(indexData)
    fields_list = indexData.get(alias_name, [])
    print(fields_list) # Assuming this function returns a list of aliases
    context = {
        'fields': fields_list # Add aliases to context
    }
    return render(request, 'data_view.html', context)

def create_data_view(request):
    alias_name = request.session.get('alias_name', None)  # Retrieve from session
    workspace_name = request.session.get('workspace_name', None)  # Retrieve from session
    request.session['data_view_name'] = workspace_name  # Store in session
   
    time_field_name = request.POST.get('time-field-name')
    create_data_view_(alias_name,time_field_name,workspace_name,request)
    return redirect("dashborad")

def get_all_dashboards():
    endpoint = f"{settings.KIBANA_HOST}/api/saved_objects/_find?type=dashboard"
    try:
        response = requests.get(endpoint, headers=headers, timeout=10)
        response.raise_for_status()
        dashboards = response.json().get('saved_objects', [])
        dashboards_info = [
            {'id': dashboard.get('id'), 'title': dashboard.get('attributes', {}).get('title')}
            for dashboard in dashboards
        ]
        print("Retrieved dashboards successfully.")
        return dashboards_info
    except RequestException as e:
        print(f"Failed to retrieve dashboards: {e}")
        return None



def get_dashboard_template_attributes(template_dashboard_id):
    """
    Get the attributes of a template dashboard from Kibana.

    :param settings.KIBANA_HOST: The base URL for the Kibana instance (e.g., "http://localhost:5601").
    :param template_dashboard_id: The ID of the template dashboard to copy.
    :param auth: Optional tuple (username, password) for Basic Authentication.
    :return: Dashboard attributes or None if the request fails.
    """
    headers = {
        'kbn-xsrf': 'true',
        'Content-Type': 'application/json',
        'Elastic-Api-Version': '2023-10-31'
    }

    # Construct the API endpoint for getting the template dashboard
    endpoint = f"{settings.KIBANA_HOST}/api/saved_objects/dashboard/{template_dashboard_id}"

    # Make the GET request to retrieve the template dashboard
    response = requests.get(endpoint, headers=headers, auth=auth)

    if response.status_code == 200:
        return response.json().get('attributes', {})
    else:
        print(f"Failed to retrieve template dashboard: {response.status_code} - {response.text}")
        return None
    
def create_new_dashboard(original_dashboard_id , new_title , new_data_view_id,request):
    """_summary_  
    # Function to copy an existing dashboard and assign a new data view


    Args:
        original_dashboard_id (_type_): _description_
        new_title (_type_): _description_
        new_data_view_id (_type_): _description_

    Returns:
        _type_: _description_
    """
    # Fetch the original dashboard
    new_id = uuid.uuid4()
    url = f"{settings.KIBANA_HOST}/api/saved_objects/dashboard/{original_dashboard_id}"
    response = requests.get(url, headers=headers)
    response.raise_for_status()
    original_dashboard = response.json()
    new_dashboard = copy.deepcopy(original_dashboard)
    

    new_dashboard['attributes']['title'] = new_title

    
    
    id_value = next((ref['id'] for ref in new_dashboard['references'] if ref['type'] == 'index-pattern'), None)
    for reference in new_dashboard.get("references", []):
        if reference.get("id") == id_value:
            reference["id"] = new_data_view_id
    
    # new_dashboard = json.loads(json.dumps(new_dashboard).replace(id_value,new_data_view_id))
    
    payload={"attributes": new_dashboard["attributes"],"references":new_dashboard["references"]}    
    response = requests.post(f"{settings.KIBANA_HOST}/api/saved_objects/dashboard/{new_id}", headers=headers,data=json.dumps(payload))

    
    # Check the result of the POST request
    if response.status_code == 200:
        # Parse the response to extract the new dashboard's ID
        new_dashboard_id = response.json()['id']
        request.session['dashboard_ids'] = new_dashboard_id
        print(f"New dashboard created successfully with ID: {new_dashboard_id}")
    else:
        print(f"Failed to create the new dashboard: {response.text}")

def dashborad(request):
    dashboards = get_all_dashboards()
    print(dashboards)
    tabss = [{"id": "tab1", "label": "Tab 1",}]
    context = { 'tabs':  tabss,'dashboards' :dashboards}
    return render(request,'new_dashboard.html',context)

def create_dashborad(request):
    
    data_view_id = request.session.get('data_view_id', None)
    workspace_name = request.session.get('workspace_name', None)
    if request.method == 'POST':
        dashboard_id = "659f2ea1-4599-4cd9-9044-d6fcf2adb617"
        time.sleep(1)
        create_new_dashboard(dashboard_id,workspace_name,data_view_id,request)
    return redirect("generate_embed_link")

def generate_embed_link(request):
    
    dashboardId = request.session.get('dashboard_ids', None)
    
    
    """
    Generate an HTML iframe embed link for a specified Kibana dashboard.

    This function constructs a complete iframe element that embeds the
    Kibana dashboard specified by the given dashboard ID. It renders
    the iframe in a template with the specified base URL for the Kibana server.

    Parameters:
    ----------
    request : HttpRequest
        The HTTP request object used to render the template.
    
    dashboard_id : str
        The unique identifier of the Kibana dashboard to embed.

    base_url : str, optional
        The base URL of the Kibana server. Defaults to the value of `settings.KIBANA_HOST`.

    Returns:
    -------
    HttpResponse
        An HTTP response that renders the `embeded_dashboard.html` template 
        with the generated iframe embed link as context.
    """
    embed_params = "?embed=true&_g=(refreshInterval%3A(pause%3A!t%2Cvalue%3A60000)%2Ctime%3A(from%3Anow-15m%2Cto%3Anow))&show-query-input=true&show-time-filter=true&hide-filter-bar=true"
    embed_link = f"<iframe src='{settings.KIBANA_HOST}/app/dashboards#/view/659f2ea1-4599-4cd9-9044-d6fcf2adb617{embed_params}' height='700' width='1600'></iframe>"

    return render(request, 'generate_embed_link.html', context={'embed_link': embed_link,'link':"192.168.17.131:8000i[ip/manage/fetch_data/"})
  
def display_data_stream_mapping(request,selectedDatabase):
    print("display_data_stream_mapping")
    """
    Displays the entire mapping of the selected data stream's backing indices.

    Parameters:
    - data_stream_name: The name of the selected data stream.
    """
    response = requests.get(f'settings.ES_HOST/_data_stream/{selectedDatabase}')
    if response.status_code == 200:
        data_stream_info = response.json()
        backing_indices = data_stream_info['data_streams'][0].get('indices', [])
        
        if backing_indices:
            # Get the latest (most recent) backing index
            latest_index_name = backing_indices[-1]['index_name']
            
            # Retrieve and display the mapping for the latest backing index
            mapping_response = requests.get(f'settings.ES_HOST/{latest_index_name}/_mapping')
            
            if mapping_response.status_code == 200:
                mapping = mapping_response.json()
                properties = mapping[latest_index_name]['mappings']['properties']
                known_fields = []  

                print(f"\nFields in the most recent backing index '{latest_index_name}':")
                
                def list_fields(fields, parent=""):
                    for field, attributes in fields.items():
                        full_field_name = f"{parent}.{field}" if parent else field
                        field_type = attributes.get('type', 'object')
                        # print(f"{full_field_name} ({field_type})")

                        if field_type != 'object':
                            known_fields.append(full_field_name)
                        
                        # If the field is an object, list its nested fields
                        if field_type == 'object' and 'properties' in attributes:
                            list_fields(attributes['properties'], full_field_name)

                if properties:
                    list_fields(properties)

                    if known_fields:
                        return JsonResponse({'columns': known_fields})
                        for field, field_type in known_fields:
                            print(f"- {field}: {field_type}")
                    else:
                        print("No fields with known types found in the selected index.")
                        return []
                
            else:
                print(f"Failed to retrieve mapping for index '{latest_index_name}'. HTTP Status Code: {mapping_response.status_code}")
        else:
            print("No backing indices found for the selected data stream.")
    else:
        print(f"Failed to retrieve data stream details for '{selectedDatabase}'. HTTP Status Code: {response.status_code}")

def get_all_indices() -> list[str]:
    """
    Get all indices in the Elasticsearch cluster.

    Returns:
        A list of index names if successful, None otherwise.
    """

    # Try to fetch the information about all indices
    # try:
    indices = settings.ES.cat.indices(format='json')
    non_system_indices = [index['index'] for index in indices if not index['index'].startswith('.')]
    return non_system_indices
    # except ElasticsearchException as e:
    #     # If an exception occurs, print it a  nd return None
    #     print(f"Error getting all indices: {e}")
    #     return None

def standard_search(request):

    """
    Perform a search on the specified Elasticsearch index with the provided term.

    Args:
        query (str): The term or query string to search for.

    Returns:
        list[Dict[str, str]]: A list of dictionaries containing the matching documents.

    Raises:
        ElasticsearchException: If an error occurs during the search process.
    """
    
    # Get the form data
    quary_term = request.POST.get('s')

    # Validate and normalize the query term
    if not quary_term or len(quary_term) <= 1:
        redirect('search')
    try:
        quary_term = quary_term.strip().lower()
        print(quary_term)
        # Check if the index exists and is valid
    except Exception as e:
        print(f"Error: {e}")
        # return []
        redirect('search')    
    try:
        response_disct = []
        indexies = get_all_indices()

        for index_name in indexies:
            response = settings.ES.search(
                index=index_name,
                body={
                    "query": {
                        "query_string": {
                        "query": quary_term
                        }
                    }
                }
            )
            hits = response['hits']['hits']
            if len(hits) > 0:  
                source = [hit["_source"] for hit in hits]                
                response_disct.append({'index_name':index_name,'result':source})
        if len(response_disct) > 0:
            # redirect('search_result')
            # search_result(request,response_disct)
            pprint.pprint(response_disct)
            return render(request, 'result.html',context={'response':response_disct})

        else:
            redirect('search')
        # return render(request, 'search.html', context = {'result':page_obj})
    except Exception as e:
        print(f"Error: {e}")
        return render(request, 'search.html')



def viewdashboard(request):
    
    dashboardId = request.session.get('dashboard_ids', None)
   
    embed_params = "?embed=true&_g=(refreshInterval%3A(pause%3A!t%2Cvalue%3A60000)%2Ctime%3A(from%3Anow-15m%2Cto%3Anow))&show-query-input=true&show-time-filter=true&hide-filter-bar=true"
    embed_link = f"<iframe src='{settings.KIBANA_HOST}/app/dashboards#/view/{dashboardId}{embed_params}' height='700' width='1600'></iframe>"

    return render(request, 'generate_embed_link.html', context={'embed_link': embed_link,'link':"192.168.17.131:8000i[ip/manage/fetch_data/"})