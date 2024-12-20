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
    error_message = ""  # Initialize the error message variable
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')

        try:
            # Assert that username and password are provided
            assert username, "Username is required"
            assert password, "Password is required"

            # Authenticate user
            user = authenticate(username=username, password=password)

            # Assert that the user is valid
            assert user is not None, "Invalid username or password"

            # If no assertion failed, log the user in
            refresh = RefreshToken.for_user(user)
            user_serializer = UserSerializer(user)
            request.session['auth_token'] = str(refresh.access_token)
            login(request, user)
            return redirect('list_user_workspaces')

        except AssertionError as e:
            # If an assertion fails, capture the error message
            error_message = str(e)

    # Pass the error message to the template if there is any
    return render(request, 'login.html', {'error_message': error_message})

def loginPage(request):
    tabss = [{"id": "Content"}]
    context = {
        'tabs': tabss,
        'error_message': request.GET.get('error_message', '')  # Add error message to context
    }
    return render(request, 'login.html', context)

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
    return render(request,'welcome_dani.html',context = recent_workspaces)
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
        assert user_indices, "User indices parameter is missing or empty."

        # Define endpoint
        endpoint = f"{settings.ES_HOST}/{user_indices}/_mapping"
        headers = {"Content-Type": "application/json"}
        
        # Send request
        response = requests.get(endpoint, headers=headers, timeout=10)
        assert response.status_code == 200, (
            f"Failed to retrieve mappings for index '{user_indices}'. "
            f"HTTP Status Code: {response.status_code}."
        )

        # Parse the response JSON
        mapping = response.json()
        index_mapping = mapping.get(user_indices, {})
        properties = index_mapping.get('mappings', {}).get('properties', {})

        assert properties, "No properties found in the selected index mapping."

        # Traverse and collect fields
        known_fields = []

        def traverse_fields(fields, parent_field=""):
            for field, attributes in fields.items():
                full_field_name = f"{parent_field}.{field}" if parent_field else field
                field_type = attributes.get('type', 'object')

                if field_type != 'object':
                    known_fields.append(full_field_name)

                if field_type == 'object' and 'properties' in attributes:
                    traverse_fields(attributes['properties'], full_field_name)

        traverse_fields(properties)

        assert known_fields, "No fields with known types found in the selected index."

        # Return the collected fields
        return JsonResponse({'columns': known_fields})
    
    except AssertionError as error_message:
        # Log or handle assertion error
        print(f"Assertion Error: {error_message}")
        return JsonResponse({'error': str(error_message)}, status=400)
    except requests.exceptions.RequestException as e:
        # Handle network-related errors
        print(f"An error occurred while fetching the mappings: {e}")
        return JsonResponse({'error': "Error while connecting to Elasticsearch."}, status=500)
    except Exception as e:
        # Catch-all for unexpected errors
        print(f"Unexpected error: {e}")
        return JsonResponse({'error': "An unexpected error occurred."}, status=500)

def input_filter_values(input_data, is_csv=True):
    filters_map = {}

    if is_csv:
        assert input_data, "Error: No input data provided for CSV."
        
        try:
            with open(input_data, newline='') as csvfile:
                reader = csv.reader(csvfile)
                headers = next(reader, None)  # Get the first row as headers
                assert headers, "Error: The CSV file is empty or missing headers."
                
                for row in reader:
                    if row:  # Check if the row is not empty
                        for i, value in enumerate(row):
                            field = headers[i] if i < len(headers) else f"field_{i}"
                            filters_map.setdefault(field, []).append(value)
        except FileNotFoundError:
            raise FileNotFoundError(f"Error: The file at {input_data} was not found.")
        except Exception as e:
            raise Exception(f"Unexpected error while processing the CSV: {e}")
    else:
        assert isinstance(input_data, list), "Error: Input data must be a list of tuples when is_csv is False."
        for field_name, value in input_data:
            value_list = [v.strip() for v in value.split(',')]
            filters_map.setdefault(field_name, []).extend(value_list)

    return filters_map


# Supported databases
supported_databases = ['postgresql', 'mysql']

def create_filter_body(filter_list, field):
    """
    Iterate over filter_list items, then check if the filter_field is in field and add terms filters.

    Parameters:
    - filter_list: A dictionary mapping fields to their filter values.
    - field: Selected fields.

    Returns:
    - filter_should: Create terms query with the matched field and values.
    """
    assert isinstance(filter_list, dict), "filter_list must be a dictionary."
    assert isinstance(field, list), "field must be a list of available fields."

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
         
        
def create_alias(selected_index, filter_body, workspace_name, request):
    """
    Create aliases on Elasticsearch.

    Parameters: 
    - selected_index: Index name
    - filter_body: Created terms query
    - workspace_name: Name of created workspace
    """
    # Assertions to validate input
    assert isinstance(selected_index, str) and selected_index.strip(), "selected_index must be a non-empty string."
    assert isinstance(filter_body, list), "filter_body must be a list."
    assert isinstance(workspace_name, str) and workspace_name.strip(), "workspace_name must be a non-empty string."
    assert request is not None, "request must not be None."

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

        response = requests.post(settings.ES_HOST + '/_aliases', json=body)
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
    """
    Handle the creation of aliases based on user input and CSV data.
    
    Parameters:
    - request: The HTTP request object containing POST data and files.
    
    Returns:
    - Redirects to the "data_view" page after processing.
    """
    # Assert that the request method is POST
    assert request.method == 'POST', "Invalid request method. POST required."

    # Convert items to a list
    post_items = list(request.POST.items())

    # Exclude the last element and get items after the 4th
    filtered_items = post_items[4:-1]  # Start from the 5th item and exclude the last

    # Create a list of tuples with the results
    result = [(field_name, value) for field_name, value in filtered_items]

    # Retrieve necessary POST data
    workspace_name = request.POST.get('workspace_name')
    columns = request.POST.getlist('columns[]')
    index_name = request.POST.get('database_type')
    csv_file = request.FILES.get('csv_file') 

    # Assertions to validate input data
    assert workspace_name and workspace_name.strip(), "Workspace name is required and cannot be empty."
    assert isinstance(columns, list) and columns, "Columns must be a non-empty list."
    assert index_name and index_name.strip(), "Database type (index name) is required and cannot be empty."

    if csv_file:
        # Assert that the uploaded file is a CSV
        assert csv_file.name.endswith('.csv'), "Uploaded file must be a CSV."

        fs = FileSystemStorage()
        filename = fs.save(csv_file.name, csv_file)
        csv_file_path = os.path.join(settings.MEDIA_ROOT, filename)

        # Assert that the file was saved successfully
        assert os.path.exists(csv_file_path), f"CSV file was not saved correctly at {csv_file_path}."

        filters = input_filter_values(csv_file_path, is_csv=True)
        # Assert that filters were successfully created
        assert filters, "Failed to create filters from the CSV file."
        filter_body = create_filter_body(filters, columns)
    else:
        # Assert that result has the expected structure
        assert isinstance(result, list), "Result must be a list of tuples."
        filters = input_filter_values(result, is_csv=False)
        # Assert that filters were successfully created
        assert filters, "Failed to create filters from the provided input."
        filter_body = create_filter_body(filters, columns)

    # Assert that filter_body is a list
    assert isinstance(filter_body, list), "Filter body must be a list."

    # Create the alias
    create_alias(index_name, filter_body, workspace_name, request) 

    return redirect("data_view")

def get_date_fields_for_alias(request, specific_alias):
    """
    Retrieve date fields for a specific Elasticsearch alias.
    
    Parameters:
    - request: The HTTP request object containing session data.
    - specific_alias (str): The alias for which date fields are to be retrieved.
    
    Returns:
    - dict or None: A dictionary mapping the alias to its date fields, or None if not found.
    """
    # Assert that specific_alias is provided and is a string
    assert isinstance(specific_alias, str) and specific_alias.strip(), "specific_alias must be a non-empty string."

    work_type = request.session.get('work_type', None)

    # Assert that work_type is provided and valid
    assert work_type in ['datastream', 'other_valid_types'], "Invalid or missing work_type in session."

    es = Elasticsearch([settings.ES_HOST])

    try:
        response = es.indices.get_alias()
        assert isinstance(response, dict), "Elasticsearch response for get_alias is not a dictionary."

        alias_found = False
        date_fields = {}

        for index, data in response.items():
            if specific_alias in data.get('aliases', {}):
                alias_found = True
                field_response = es.indices.get_mapping(index=index)
                assert index in field_response, f"Index '{index}' not found in mapping response."
                fields = field_response[index]['mappings']['properties']

                if work_type == 'datastream':
                    ds_endpoint = f"{settings.ES_HOST}/_data_stream/{index}"
                    ds_response = requests.get(ds_endpoint, timeout=10)
                    ds_response.raise_for_status()
                    data_stream_info = ds_response.json()
                    backing_indices = data_stream_info['data_streams'][0].get('indices', [])
                    assert backing_indices, "No backing indices found for the data stream."
                    latest_index_name = backing_indices[-1]['index_name']
                    assert latest_index_name in field_response, (
                        f"Latest index '{latest_index_name}' not found in mapping response."
                    )
                    fields = field_response[latest_index_name]['mappings']['properties']

                # Collect date fields
                date_fields = {
                    field_name: field_info
                    for field_name, field_info in fields.items()
                    if field_info.get('type') == 'date'
                }

        assert alias_found, f"Alias '{specific_alias}' not found in any index."

        return {specific_alias: list(date_fields.keys())} if date_fields else {}
    
    except (ElasticsearchException, RequestException) as e:
        print(f"Error retrieving date fields for alias '{specific_alias}': {e}")
        return None
    except AssertionError as e:
        print(f"Assertion Error: {e}")
        return None
    except Exception as e:
        print(f"Unexpected error retrieving date fields for alias '{specific_alias}': {e}")
        return None
# es = Elasticsearch([{'host': '192.168.6.175', 'port': 9200, 'scheme': 'http'}])
def fetch_from_elasticsearch(request):
    """
    Fetch data from Elasticsearch for a specific alias.
    
    Parameters:
    - request: The HTTP request object containing session data.
    
    Returns:
    - JsonResponse: JSON response with fetched data or an error message.
    """
    # Assert that the alias_name exists in the session
    alias_name = request.session.get('alias_name', None)
    assert alias_name, "Alias name not found in session. Cannot fetch data."

    print(f"Fetching data from Elasticsearch for alias: {alias_name}")

    query = {
        "_source": ["From", "location", "imsi", "To", "duration", "City_name"],
        "query": {"match_all": {}},
        "size": 10000
    }

    try:
        # Assert Elasticsearch settings are configured
        assert hasattr(settings, 'ES'), "Elasticsearch settings (ES) are not configured."

        # Perform the Elasticsearch query
        response = settings.ES.search(index=alias_name, body=query)

        # Assert that the response contains hits
        assert 'hits' in response and 'hits' in response['hits'], "Elasticsearch response is missing 'hits'."

        result = [hit['_source'] for hit in response['hits']['hits']]
        return JsonResponse(result, safe=False)
    except ElasticsearchException as e:
        error_message = {"error": str(e)}
        return JsonResponse(error_message, status=500)

def create_data_view_(data_view_index_pattern, time_field_name, data_view_name, request):
    """
    Create a new data view in Kibana.
    
    Parameters:
    - data_view_index_pattern (str): The index pattern for the data view.
    - time_field_name (str): The field to use for time-based data.
    - data_view_name (str): The name of the data view.
    - request: The HTTP request object containing session data.
    
    Returns:
    - dict or None: The created data view information or None if an error occurs.
    """
    # Assertions to validate inputs
    assert data_view_index_pattern and isinstance(data_view_index_pattern, str), \
        "Data view index pattern must be a non-empty string."
    assert time_field_name and isinstance(time_field_name, str), \
        "Time field name must be a non-empty string."
    assert data_view_name and isinstance(data_view_name, str), \
        "Data view name must be a non-empty string."

    # Assert that Kibana settings are configured
    assert hasattr(settings, 'KIBANA_HOST'), "Kibana host settings are not configured."
    assert hasattr(settings, 'auth'), "Authentication settings for Kibana are not configured."

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
        # Ensure headers are provided
        assert 'headers' in globals(), "Headers for the Kibana request are not defined."

        # Perform the POST request
        response = requests.post(endpoint, headers=headers, data=json.dumps(data_view_payload), auth=auth, timeout=10)

        # Assert that the response status is successful
        assert response.status_code == 200, f"Kibana API returned an unexpected status: {response.status_code}"

        response.raise_for_status()
        data_view = response.json().get('data_view', {})
        
        # Assert the data_view contains the 'id'
        assert 'id' in data_view, "Created data view does not contain an 'id'."

        # Store the data view ID in the session
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
    
    # Initialize variables for error message and response
    error_message = None
    response_dict = []

    # Get the query term from the request
    query_term = request.POST.get('search')

    try:
        # Validate the query term with assertions
        assert query_term, "Search term must not be empty"  # Ensure query_term is not empty
        assert len(query_term.strip()) > 1, "Search term must have more than 1 character"  # Ensure it's long enough

        # Normalize the query term
        query_term = query_term.strip().lower()

        # Perform Elasticsearch search
        indices = get_all_indices()
        assert indices, "No indices found in Elasticsearch"  # Assert that indices are available

        for index_name in indices:
            try:
                assert isinstance(index_name, str) and len(index_name) > 0, f"Invalid index name: {index_name}"

                response = settings.ES.search(
                    index=index_name,
                    body={
                        "query": {
                            "query_string": {
                                "query": query_term
                            }
                        }
                    }
                )
                hits = response.get('hits', {}).get('hits', [])
                assert isinstance(hits, list), "Hits should be a list"

                if hits:
                    source = [hit["_source"] for hit in hits]
                    response_dict.append({'index_name': index_name, 'result': source})
                else:
                    response_dict.append({'index_name': index_name, 'message': "No results found in this index."})

            except Exception as e:
                error_message = f"Error searching index '{index_name}': {e}"
                response_dict.append({'index_name': index_name, 'error': error_message})

        # If no results are found, set an appropriate message
        if not response_dict:
            error_message = "No results found in any of the indices."

    except AssertionError as e:
        # Catch assertion errors and show them on the same page
        error_message = str(e)

    except Exception as e:
        # Catch any other unexpected errors
        error_message = f"Error during search operation: {e}"

    # Render the search page with either results or error messages
    return render(request, 'search_dani.html', {'error_message': error_message, 'query_term': query_term, 'response': response_dict})
def viewdashboard(request):
    
    dashboardId = request.session.get('dashboard_ids', None)
   
    embed_params = "?embed=true&_g=(refreshInterval%3A(pause%3A!t%2Cvalue%3A60000)%2Ctime%3A(from%3Anow-15m%2Cto%3Anow))&show-query-input=true&show-time-filter=true&hide-filter-bar=true"
    embed_link = f"<iframe src='{settings.KIBANA_HOST}/app/dashboards#/view/{dashboardId}{embed_params}' height='700' width='1600'></iframe>"

    return render(request, 'generate_embed_link.html', context={'embed_link': embed_link,'link':"192.168.17.131:8000i[ip/manage/fetch_data/"})



# update_alise page------------------------------------------------ 


 
def update_alias_page(request):
    """
    Handles the rendering of the alias update page.

    Args:
        request: HTTP request object.

    Returns:
        A rendered template for updating aliases with a context containing alias data.
    """ 
    aliases = get_aliases()
  
    context = {
        'aliase_data': aliases
    }
    return render(request, 'update_alias.html', context)

def get_aliases():
    """
    Fetches a list of aliases from the Elasticsearch instance.

    Returns:
        A list of aliases that do not start with a dot.
    """
    try:
        response = requests.get('http://192.168.6.175:9200/_cat/aliases?v&h=alias&format=json')
        response.raise_for_status()
        all_indices = response.json()
        user_indices = [alias['alias'] for alias in all_indices if not alias['alias'].startswith('.')]
        return user_indices
    except requests.RequestException as e:
        print(f"Error fetching aliases: {e}")
        return []
def search_alias_mapping(selected_alias):
    """
    Retrieves field names from the mappings of a specified alias.

    Args:
        selected_alias (str): The name of the alias to search.

    Returns:
        A list of field names associated with the alias.
    """
    try:
        response = requests.get(f'http://192.168.6.175:9200/{selected_alias}/_mapping')
        response.raise_for_status()
        alias_mappings = response.json()
        field_names = []
        for index_name, mapping_data in alias_mappings.items():
            properties = mapping_data.get('mappings', {}).get('properties', {})
            field_names.extend(properties.keys())
        return field_names
    except requests.RequestException as e:
        print(f"Error fetching alias mapping: {e}")
        return []

def search_alias(selected_alias):
    """
    Fetches details of an alias, including terms associated with fields.

    Args:
        selected_alias (str): The alias name.

    Returns:
        A dictionary mapping fields to their associated terms.
    """
    try:
        response = requests.get(f'http://192.168.6.175:9200/_alias/{selected_alias}')
        response.raise_for_status()
        alias_mappings = response.json()

        # print(f"Alias Mappings for '{selected_alias}':")
        # print(json.dumps(alias_mappings, indent=4)) 


        field_terms = {}
        for alias, alias_data in alias_mappings.items():

            aliases_info = alias_data.get('aliases', {}).get(selected_alias, {})
            filter_conditions = aliases_info.get('filter', {}).get('bool', {}).get('should', [])

            for condition in filter_conditions:
                if 'terms' in condition:
                    for field, terms in condition['terms'].items():
                        if field not in field_terms:
                            field_terms[field] = set()  
                        field_terms[field].update(terms)  

        # Convert sets to lists
        consolidated_terms = {field: list(terms) for field, terms in field_terms.items()}

        # print(f"Consolidated Terms for '{selected_alias}': {json.dumps(consolidated_terms, indent=4)}")
        return consolidated_terms
        
    except requests.RequestException as e:
        print(f"Error fetching alias details: {e}")
        return {}

    except KeyError as e:
        print(f"Error processing alias mappings: {e}")
        return {}

def select_alias(request, user_alias):
    """
    Fetches combined terms and fields for a given alias.

    Args:
        request: HTTP request object.
        user_alias (str): The alias name.

    Returns:
        A JSON response containing fields and associated terms.
    """
    terms_fields = search_alias(user_alias)

    field_names = search_alias_mapping(user_alias)

    # Combine terms and field names
    combined_result = []
    for field, terms in terms_fields.items():
        if field in field_names:

            combined_result.append({"field": field, "terms": terms})

    for field in field_names:
        if field not in terms_fields:
            combined_result.append({"field": field, "terms": []})
    
    return JsonResponse({'columns': combined_result})


es_host = "http://192.168.6.175:9200" # Adjust host/port if necessary


# Function to generate filter body
def create_filter_body(filter_list, fields):
    """
    Generates a terms query for Elasticsearch based on filter_list and fields.

    Parameters:
    - filter_list: Dictionary with fields as keys and their values as lists.
    - fields: List of field names.

    Returns:
    - List of terms queries for Elasticsearch.
    """
    filter_should = []

    for field in fields:
        if field in filter_list:
            values = filter_list[field]
            for term in values:
                if term and term.strip():
                    filter_should.append({"terms": {field: [term.strip()]}})
        else:
            print(f"Field '{field}' not found in filter list.")

    print(f"Generated filter body: {filter_should}")
    return filter_should

# Function to fetch index name from alias
def get_index_name(selected_alias):
    """
    Retrieves the index name associated with a given alias.

    Args:
        selected_alias (str): The alias name.

    Returns:
        The index name associated with the alias or None if not found.
    """
    
    try:
        response = requests.get(f'http://192.168.6.175:9200/_alias/{selected_alias}')
        response.raise_for_status()
        alias_mappings = response.json()
       
        root_name = next(iter(alias_mappings.keys()), None)  # Get the first key (index name)
        print(f"Index name for alias '{selected_alias}': {root_name}")
        return root_name
    except Exception as e:
        print(f"Error fetching index name for alias '{selected_alias}': {e}")
        return None

# Function to update an alias
def update_alias(filter_body, alias_name):
    """
    Updates an alias with the specified filter.

    Args:
        filter_body (list): Filter body to apply to the alias.
        alias_name (str): The alias name to update.
    """
  
    selected_index = get_index_name(alias_name)
    if not selected_index:
        print(f"No index found for alias '{alias_name}'.")
        return

    if filter_body:
        body = {
            "actions": [
                {
                    "add": {
                        "index": selected_index,
                        "alias": alias_name,
                        "filter": {"bool": {"should": filter_body}}
                    }
                }
            ]
        }

        response = requests.post('http://192.168.6.175:9200/_aliases', json=body)
        if response.status_code == 200:
            print(f"Alias '{alias_name}' updated successfully.")
        else:
            print(f"Failed to update alias '{alias_name}'. HTTP Code: {response.status_code}")
    else:
        print("Filter body is empty. Alias update aborted.")

# Wrapper to handle alias update requests
def combine_terms_and_fields(selected_alias):
    """
    Combines terms and fields from alias mappings.

    Args:
        selected_alias: The alias to query.

    Returns:
        A list of dictionaries with fields and their associated terms.
    """

    terms_fields = search_alias(selected_alias)

    field_names = search_alias_mapping(selected_alias)

    # Combine terms and field names
    combined_result = []
    for field, terms in terms_fields.items():
        if field in field_names:

            combined_result.append({"field": field, "terms": terms})

    for field in field_names:
        if field not in terms_fields:
            combined_result.append({"field": field, "terms": []})

    return combined_result

def update_alias__(request):
    """
    Handles POST requests to update an alias based on user input.

    Args:
        request: HTTP request object containing POST data.

    Returns:
        A redirect to the alias update page or a JSON response in case of an error.
    """
    if request.method == "POST":
        try:
            # Get the selected alias from POST data
            alias = request.POST.get('database_type')
            
            # Assuming `combine_terms_and_fields` processes data based on alias
            combined_data = combine_terms_and_fields(alias)
            print(request.POST)
            if combined_data:
                # Create filter list based on combined data
                filter_list = {item['field']: item['terms'] for item in combined_data}
                fields = [item['field'] for item in combined_data]

                # Debug print to check the values of filter_list and fields
                print("filter_list before calling create_filter_body:")
                print(filter_list)
                print("fields before calling create_filter_body:")
                print(fields)

                # Process the incoming data and update filter_list
                print(request.POST)
                for column in request.POST:
                    value = request.POST.getlist(column)
                    print("value ab")
                    print(column)
                    print(value)
                    print("value bel")
                    if column in filter_list:  # Ensure the column exists in filter_list
                        # Split value by commas and trim whitespace
                        filter_list[column] = [item.strip() for item in value]
                        print("filter_list ab")
                        print(filter_list[column])
                        print("filter_list be")
                # Debug print to check the updated filter_list
                print("Updated filter_list after processing POST data:")
                print(filter_list)

                # Now call create_filter_body
                filter_body = create_filter_body(filter_list, fields)

                # Print filter_body for debugging
                print("filter_body:")
                print(filter_body)

                # Now update the alias
                update_alias(filter_body, alias)

            # return JsonResponse({'success': True, 'message': 'Alias updated successfully.'})
            return redirect('update_alias_page')
        except Exception as e:
            print(f"Error: {e}")  # Log the error for debugging
            return JsonResponse({'success': False, 'message': str(e)}, status=500)

    else:
        return JsonResponse({'success': False, 'message': 'Invalid request method.'}, status=400)
def search_alias__(request):
    """
    Purpose: 
    """
    return render(request, 'search_dani.html')
def welcome__dani(request):
    """
    Purpose: Handle rendering of the welcome page with error handling for network issues.
    """
    try:
        # Example: Fetch recent workspaces or other data (you might have a database or API call)
        # Simulate a potential request to fetch recent workspaces or something from a server.
        response = requests.get('http://example.com/api/recent-workspaces')  # Example API URL
        response.raise_for_status()  # Raise an exception for bad responses
        recent_workspaces = response.json()  # Assuming JSON response with workspace data

        return render(request, 'welcome_dani.html', {'recent_workspaces': recent_workspaces})
    
    except requests.ConnectionError:
        # Handle no internet connection or unable to reach the server
        return render(request, 'welcome_dani.html', {'error_message': "It seems like there's no internet connection. Please check your connection and try again."})

    except requests.Timeout:
        # Handle server timeout errors
        return render(request, 'welcome_dani.html', {'error_message': "The server took too long to respond. Please try again later."})
    
    except requests.RequestException as e:
        # Handle any other HTTP error (server down, invalid response, etc.)
        return render(request, 'welcome_dani.html', {'error_message': "We're experiencing some issues with the server. Please try again later."})

    except Exception as e:
        # Catch any other unexpected errors
        return render(request, 'welcome_dani.html', {'error_message': f"An unexpected error occurred: {str(e)}"})
# end def