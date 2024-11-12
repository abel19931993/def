import requests
import json,copy
from elasticsearch import Elasticsearch
import time
import csv
from rest_framework.response import Response
from rest_framework import permissions, status
from django.http import HttpResponse, JsonResponse
from rest_framework import status
from django.contrib.auth.hashers import make_password 
import os
from django.conf import settings
from django.core.files.storage import FileSystemStorage
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from .serializers import *
from .permissions import *
from .models import *
from rest_framework.decorators import api_view, permission_classes
from rest_framework.views import APIView
from django.shortcuts import render,redirect
from .serializers import *
from rest_framework.permissions import IsAuthenticated

# Kibana server details
kibana_host = "http://192.168.6.175:5601" 
es_host = "http://192.168.6.175:9200"
headers = {
    'Content-Type': 'application/json',
    'kbn-xsrf': 'true'  # Required header for Kibana API requests
}

class SystemUserStaffPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        # Check if any of the required permissions are met
        return request.user.is_authenticated and (
           IsAdmin().has_permission(request, view)
        )
workspace_name = None  
alias_name = None
data_view_name = None
dashboard_ids = None
work_type = None
def list_user_indices():
    response = requests.get('http://192.168.6.175:9200/_cat/indices?v&h=index&format=json')
    all_indices = response.json()
    user_indices = [index['index'] for index in all_indices if not index['index'].startswith('.')]
    return user_indices
def get_data_views():
    """
    Get all data views from Kibana.

    :param kibana_host: The base URL for the Kibana instance (e.g., "http://localhost:5601").
    :param auth: Optional tuple (username, password) for Basic Authentication.
    :return: List of data views or None if the request fails.
    """
    
    # Construct the API endpoint for getting data views
    endpoint = f"{kibana_host}/api/data_views"

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
            data_views_info.append(view_info)

        print("Retrieved data views info successfully.")
        return data_views_info
    else:
        print(f"Failed to retrieve data views: {response.status_code} - {response.text}")
        return None
    
def get_data_stream_names():
    response = requests.get('http://192.168.6.175:9200/_data_stream')
    all_data_streams = response.json()
    
    # Extract names of data streams, excluding system data streams
    data_stream_names = [
        ds['name'] for ds in all_data_streams['data_streams'] 
        if not ds.get('system', False)  # Exclude if 'system' is True
    ]
    
    print(data_stream_names)
    return data_stream_names

# Example usage
kibana_host = "http://192.168.6.175:5601"
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
    return render(request, 'filter.html', context={
        'supported_database': list_user_indices(),
        'workspace_name': workspace_name  # Pass the workspace name to the template
    })

def index_view(request):
    print("above index viewwwwwwwwwww")
    print(get_data_views())
    print("inside index viewwwwwwwwwwww")
    # get_all_dashboards(kibana_host)
    tabss = [
    {"id": "tab1", "label": "Tab 1",},
    {"id": "tab2", "label": "Tab 2",},
    {"id": "tab3", "label": "Tab 3", "content": "Content for Tab 3"}
]
    context = {
            'tabs':  tabss
            # Add more context variables as neededS
            }
    return render(request,'index.html',context)

# Step 3: Select index
def select_index(request, user_indices):
    print(user_indices)
    try:
        response = requests.get(f'http://192.168.6.175:9200/{user_indices}/_mapping')
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
    filter_should =[]
    common_str = "combined_docs.source."
    for filter_field, values in filter_list.items():
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
            modified_filter_field = common_str + filter_field
            if modified_filter_field in field:
                if values:
                    for value in values:
                        if value and value.strip():
                            filter_should.append(
                                {
                                    "terms": {
                                        modified_filter_field: [value]
                                    }
                                }
                            )
                else:
                    print(f"Skipping {modified_filter_field} due to empty values.")
            else:
                print(f"Neither {filter_field} nor {modified_filter_field} exist in provided field list.")
   
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

        response = requests.post('http://192.168.6.175:9200/_aliases', json=body)
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

def get_date_fields_for_alias(request,specific_alias):
    print("kkkkkkkkkkkkkkkkkk")
    work_type = request.session.get('work_type', None) 
    print(work_type)
    """
    Get all date fields for a specific user-defined alias in Elasticsearch.

    :param es_host: The Elasticsearch host (e.g., "http://localhost:9200").
    :param specific_alias: The user-defined alias to retrieve date fields for.
    :return: A dictionary containing the alias and its date fields.
    """
    # Create an Elasticsearch client
    es = Elasticsearch([es_host])

    date_fields = {}

    try:
        # Retrieve all aliases
        response = es.indices.get_alias()
       
        # Check if the specific alias exists
        alias_found = False
        for index, data in response.items():
            for alias in data['aliases']:
                if alias == specific_alias:
                   
                    alias_found = True
                    # Include all fields associated with the index of the alias
                    field_response = es.indices.get_mapping(index=index)
                    print(field_response)
                    if work_type == 'datastream':
                        response = requests.get(f'http://192.168.6.175:9200/_data_stream/{index}')
                        if response.status_code == 200:
                            data_stream_info = response.json()
                            backing_indices = data_stream_info['data_streams'][0].get('indices', [])
                            
                            if backing_indices:
                                # Get the latest (most recent) backing index
                                latest_index_name = backing_indices[-1]['index_name']
                                print("lattttttttttttttttttttttt")
                                print(latest_index_name)
                                fields = field_response[latest_index_name]['mappings']['properties']
                                print(fields)
                                # Filter fields to only include those of type 'date'
                                date_fields = {field_name: field_info for field_name, field_info in fields.items() if field_info.get('type') == 'date'}
                                print(date_fields)
                    else:
                        fields = field_response[index]['mappings']['properties']
                        print(fields)
                        # Filter fields to only include those of type 'date'
                        date_fields = {field_name: field_info for field_name, field_info in fields.items() if field_info.get('type') == 'date'}
                        print(date_fields)
        if alias_found:
            return {specific_alias: list(date_fields.keys())}  # Return a dictionary with the alias and its date field names
        else:
            print(f"Alias '{specific_alias}' not found.")
            return None
            
    except Exception as e:
        print(f"Error retrieving date fields for alias '{specific_alias}': {e}")
        return None
  
def create_data_view_(data_view_index_pattern:str, time_field_name:str, data_view_name:str, auth=None, allow_no_index=False):
    """
    Create a new data view in Kibana.

    :param data_view_name: The title of the new data view.
    :param time_field_name: The name of the time field in the index (e.g., "@timestamp").
    :param data_view_index_pattern: Comma-separated list of data streams, indices, and aliases to search.
    :param auth: Optional tuple (username, password) for Basic Authentication.
    :param allow_no_index: Allow the data view to exist without any index data.
    :return: The response from the Kibana API.
    """
  
    data_view_payload = {
        "data_view": {
            'name':data_view_name,
            "title": data_view_index_pattern,
            "timeFieldName": time_field_name,
            "allowNoIndex": allow_no_index,
            # "fields": {},  # Optional: You can specify field formats here
            # "runtimeFieldMap": {},  # Optional: Add runtime fields if needed
            # "sourceFilters": [],  # Optional: Specify source filters if needed
            # "namespaces": ["default"]  # Default namespacee
        }
    }

    # Construct the API endpoint for creating a data view
    endpoint = f"{kibana_host}/api/data_views/data_view"

    # Make the POST request to create the data view
    response = requests.post(endpoint, headers=headers, data=json.dumps(data_view_payload), auth=auth)

    if response.status_code == 200:
        print("Data view created successfully.")
        return response.json()
    else:
        print(f"Failed to create data view: {response.status_code} - {response.text}")
        return None
def get_data_views(auth=None):
    """
    Get all data views from Kibana.

    :param kibana_host: The base URL for the Kibana instance (e.g., "http://localhost:5601").
    :param auth: Optional tuple (username, password) for Basic Authentication.
    :return: List of data views or None if the request fails.
    """
    
    # Construct the API endpoint for getting data views
    endpoint = f"{kibana_host}/api/data_views"

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
    create_data_view_(data_view_index_pattern=alias_name,time_field_name=time_field_name,data_view_name=workspace_name)
    return redirect("dashborad")
def get_all_dashboards( ):
    """
    Get all dashboards from Kibana.

    :param kibana_host: The base URL for the Kibana instance (e.g., "http://localhost:5601").
    :param auth: Optional tuple (username, password) for Basic Authentication.
    :return: List of dashboards or None if the request fails.
    """
    

    # Construct the API endpoint for getting dashboards
    endpoint = f"{kibana_host}/api/saved_objects/_find?type=dashboard"

    # Make the GET request to retrieve all dashboards
    response = requests.get(endpoint, headers=headers,)

    if response.status_code == 200:
        dashboards = response.json().get('saved_objects', [])
        dashboards_info = []

        for dashboard in dashboards:
            # Extract the required fields: id and attributes
            dashboard_info = {
                'id': dashboard.get('id'),
                'title': dashboard.get('attributes', {}).get('title')
            }
            dashboards_info.append(dashboard_info)

        print("Retrieved dashboards successfully.")
        return dashboards_info
    else:
        print(f"Failed to retrieve dashboards: {response.status_code} - {response.text}")
        return None

def get_dashboard_template_attributes(template_dashboard_id):
    """
    Get the attributes of a template dashboard from Kibana.

    :param kibana_host: The base URL for the Kibana instance (e.g., "http://localhost:5601").
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
    endpoint = f"{kibana_host}/api/saved_objects/dashboard/{template_dashboard_id}"

    # Make the GET request to retrieve the template dashboard
    response = requests.get(endpoint, headers=headers, auth=auth)

    if response.status_code == 200:
        return response.json().get('attributes', {})
    else:
        print(f"Failed to retrieve template dashboard: {response.status_code} - {response.text}")
        return None
    
def create_new_dashboard(template_dashboard_id, new_dashboard_title, new_data_view_id, auth=None):
    """
    Create a new dashboard in Kibana based on a template dashboard.

    :param kibana_host: The base URL for the Kibana instance (e.g., "http://localhost:5601").
    :param template_dashboard_id: The ID of the template dashboard to copy.
    :param new_dashboard_title: The title for the new dashboard.
    :param new_data_view_id: The ID of the new data view to set in the dashboard.
    :param auth: Optional tuple (username, password) for Basic Authentication.
    :return: The response from the Kibana API.
    """
    # Get the attributes of the template dashboard
    template_attributes = get_dashboard_template_attributes( template_dashboard_id)

    if template_attributes is None:
        return None

    # Update the title and data view ID in the copied attributes
    template_attributes['title'] = new_dashboard_title

    # Replace the data view ID in the attributes (modify this key based on your template structure)
    if 'dataViewId' in template_attributes:
        template_attributes['dataViewId'] = new_data_view_id

    # Prepare the payload for creating a new dashboard
    new_dashboard_payload = {
        "attributes": template_attributes
    }

    headers = {
        'kbn-xsrf': 'true',
        'Content-Type': 'application/json',
        'Elastic-Api-Version': '2023-10-31'
    }

    # Construct the API endpoint for creating a new dashboard
    endpoint = f"{kibana_host}/api/saved_objects/dashboard"

    # Make the POST request to create the new dashboard
    response = requests.post(endpoint, headers=headers, data=json.dumps(new_dashboard_payload), auth=auth)

    if response.status_code == 200:
        print("New dashboard created successfully.")
        return response.json()
    else:
        print(f"Failed to create new dashboard: {response.status_code} - {response.text}")
        return None
def dashborad(request):
    dashboards = get_all_dashboards()
    print(dashboards)
    tabss = [{"id": "tab1", "label": "Tab 1",}]
    context = { 'tabs':  tabss,'dashboards' :dashboards}
    return render(request,'new_dashboard.html',context)

def create_dashborad(request):
    alias_names = request.session.get('data_view_name', None) 
    if request.method == 'POST':
        dashboard_id = request.POST.get('data-view-id')
        print("hiiiiiiiiiiiiiiiiiiiiiiiiiiii")
        print(dashboard_id)
        print("hiiiiiiiiiiiiiiiiiiiio")
        request.session['dashboard_ids'] = dashboard_id
        time.sleep(1)
        create_new_dashboard(dashboard_id,"index_view",alias_names)
    return redirect("generate_embed_link")

def generate_embed_link(request):
    dashboard_idss = request.session.get('dashboard_ids', None) 
    dashboard_idss = "d8450d9b-830a-4687-aa73-2d33d45f2edd"
    print ("Generating embed link")
    print(dashboard_idss)
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
        The base URL of the Kibana server. Defaults to the value of `kibana_host`.

    Returns:
    -------
    HttpResponse
        An HTTP response that renders the `embeded_dashboard.html` template 
        with the generated iframe embed link as context.
    """
    embed_params = "?embed=true&_g=(refreshInterval%3A(pause%3A!t%2Cvalue%3A60000)%2Ctime%3A(from%3Anow-15m%2Cto%3Anow))&show-query-input=true&show-time-filter=true&hide-filter-bar=true"
    embed_link = f"<iframe src='{kibana_host}/app/dashboards#/view/{dashboard_idss}{embed_params}' height='600' width='950'></iframe>"

    return render(request, 'generate_embed_link.html', context={'embed_link': embed_link})


                                  #  DATA STREAM LIST OF FUNCTIONS



# DATA STREAM LIST OF FUNCTION



   


def display_data_stream_mapping(request,selectedDatabase):
    print("display_data_stream_mapping")
    """
    Displays the entire mapping of the selected data stream's backing indices.

    Parameters:
    - data_stream_name: The name of the selected data stream.
    """
    response = requests.get(f'http://192.168.6.175:9200/_data_stream/{selectedDatabase}')
    if response.status_code == 200:
        data_stream_info = response.json()
        backing_indices = data_stream_info['data_streams'][0].get('indices', [])
        
        if backing_indices:
            # Get the latest (most recent) backing index
            latest_index_name = backing_indices[-1]['index_name']
            
            # Retrieve and display the mapping for the latest backing index
            mapping_response = requests.get(f'http://192.168.6.175:9200/{latest_index_name}/_mapping')
            
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
















