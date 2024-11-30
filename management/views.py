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
import uuid
# from django.contrib.auth.forms import CreateUserForm
from .forms import CreateUserForm
# from elasticsearch.exceptions import ElasticsearchException
from requests.exceptions import RequestException
from django.contrib import messages
from django.contrib.auth import authenticate,login,logout
from django.contrib.auth.decorators import login_required
# Kibana server details
kibana_host = "http://192.168.6.175:5601" 
es_host = "http://192.168.6.175:9200"
headers = {
    'Content-Type': 'application/json',
    'kbn-xsrf': 'true'  # Required header for Kibana API requests
}

def registerPage(request):
    print("hi;")
    form = CreateUserForm()
    if request.method == 'POST':
        form = CreateUserForm(request.POST) 
        if form.is_valid():
            form.save()
            user  = form.cleaned_data.get('username')
            messages.success(request, "Account was created for "+user)
            return redirect('loginPage')
    context = {'form':form}
    return render(request,'register.html',context)

def loginPage(request):
    if request.method == 'POST':
      username =  request.POST.get('username')
      password =  request.POST.get('password')
      user = authenticate(request,username = username,password=password)
      if user is not None:
        login(request,user)
        return redirect('index_view')
      else:
        messages.info(request,"Username OR password is incorrect")
        # return render(request,'login.html')
    context = {}
    return render(request,'login.html',context)

def logoutUser(request):
    logout(request)
    return redirect('loginPage')



























class SystemUserStaffPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        # Check if any of the required permissions are met
        return request.user.is_authenticated and (
           IsAdmin().has_permission(request, view)
        )
workspace_name = None 
police_name = None 
alias_name = None
data_view_name = None
dashboard_ids = None
work_type = None
def list_user_indices():
    try:
        response = requests.get('http://192.168.6.175:9200/_cat/indices?v&h=index&format=json', timeout=10)
        response.raise_for_status()
        all_indices = response.json()
        user_indices = [index['index'] for index in all_indices if not index['index'].startswith('.')]
        return user_indices
    except RequestException as e:
        print(f"Error fetching user indices: {e}")
        return []
@login_required(login_url='loginPage')
def get_data_views(auth=None):
    """
    Get all data views from Kibana.
    """
    endpoint = f"{kibana_host}/api/data_views"
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
        response = requests.get('http://192.168.6.12:9200/_data_stream', timeout=10)
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
@login_required(login_url='loginPage')
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
    print("hiiiiiiiiii")
    print(user_indices)
    try:
        response = requests.get(f'http://192.168.6.12:9200/{user_indices}/_mapping')
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


def get_date_fields_for_alias(request, specific_alias):
    es_host = 'http://192.168.6.175:9200'
    work_type = request.session.get('work_type', None)
    es = Elasticsearch([es_host])

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
                    ds_response = requests.get(f'http://192.168.6.175:9200/_data_stream/{index}', timeout=10)
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
    except (RequestException) as e:
        print(f"Error retrieving date fields for alias '{specific_alias}': {e}")
        return None

            
    except Exception as e:
        print(f"Error retrieving date fields for alias '{specific_alias}': {e}")
        return None
  

es = Elasticsearch([{'host': '192.168.6.175', 'port': 9200, 'scheme': 'http'}])

def fetch_from_elasticsearch(request):
    alias_name = request.session.get('alias_name', None)
    print(f"Fetching data from Elasticsearch for alias: {alias_name}")
    
    query = {
        "_source": ["From", "location", "imsi", "To", "duration", "City_name"],
        "query": {"match_all": {}},
        "size": 10000
    }
    try:
        response = es.search(index=alias_name, body=query)
        result = [hit['_source'] for hit in response['hits']['hits']]
        return JsonResponse(result, safe=False)
    except ElasticsearchException as e:
        error_message = {"error": str(e)}
        return JsonResponse(error_message, status=500)



def create_data_view_(data_view_index_pattern, time_field_name, data_view_name, auth=None, allow_no_index=False):
    """
    Create a new data view in Kibana.
    """
    data_view_payload = {
        "data_view": {
            'name': data_view_name,
            "title": data_view_index_pattern,
            "timeFieldName": time_field_name,
            "allowNoIndex": allow_no_index,
        }
    }
    endpoint = f"{kibana_host}/api/data_views/data_view"
    try:
        response = requests.post(endpoint, headers=headers, data=json.dumps(data_view_payload), auth=auth, timeout=10)
        response.raise_for_status()
        print("Data view created successfully.")
        return response.json()
    except RequestException as e:
        print(f"Failed to create data view: {e}")
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
import requests

def get_data_view_id_by_name(data_view_name, auth=None):
    """
    Get the ID of a specific data view from Kibana by its name.

    :param kibana_host: The base URL for the Kibana instance (e.g., "http://localhost:5601").
    :param data_view_name: The name of the data view to look for.
    :param auth: Optional tuple (username, password) for Basic Authentication.
    :return: The ID of the data view or None if not found or request fails.
    """
    
    # Construct the API endpoint for getting data views
    endpoint = f"{kibana_host}/api/data_views"

    # Set up headers, including authorization if provided
    headers = {
        "kbn-xsrf": "true",  # Kibana requires this header for all API requests
    }
    
    if auth:
        response = requests.get(endpoint, headers=headers, auth=auth)
    else:
        response = requests.get(endpoint, headers=headers)

    if response.status_code == 200:
        data_views = response.json().get('data_view', [])
        
        for data_view in data_views:
            if data_view.get('name') == data_view_name:
                # Return the ID of the matched data view
                return data_view.get('id')
        
        print(f"Data view with name '{data_view_name}' not found.")
        return None
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
    import requests
from requests.exceptions import RequestException



def get_dashboard_id_by_name(dashboard_name):
    endpoint = f"{kibana_host}/api/saved_objects/_find?type=dashboard"
    try:
        response = requests.get(endpoint, headers=headers, timeout=10)
        response.raise_for_status()
        dashboards = response.json().get('saved_objects', [])
        for dashboard in dashboards:
            if dashboard.get('attributes', {}).get('title') == dashboard_name:
                print(f"Dashboard '{dashboard_name}' found with ID: {dashboard.get('id')}")
                return dashboard.get('id')
        print(f"Dashboard '{dashboard_name}' not found.")
        return None
    except RequestException as e:
        print(f"Failed to retrieve dashboards: {e}")
        return None


def get_all_dashboards():
    endpoint = f"{kibana_host}/api/saved_objects/_find?type=dashboard"
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

def get_data_view_id_by_name(data_view_name, auth=None):
    endpoint = f"{kibana_host}/api/data_views"
    headers = {"kbn-xsrf": "true"}

    try:
        response = requests.get(endpoint, headers=headers, auth=auth, timeout=10)
        response.raise_for_status()
        data_views = response.json().get('data_view', [])

        for data_view in data_views:
            if data_view.get('name') == data_view_name:
                return data_view.get('id')

        print(f"Data view with name '{data_view_name}' not found.")
        return None
    except RequestException as e:
        print(f"Failed to retrieve data views: {e}")
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
    
def create_new_dashboard(original_dashboard_id , new_title , new_data_view_id):
    print(original_dashboard_id)
    print(new_title)
    print(new_data_view_id)
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

    url = f"{kibana_host}/api/saved_objects/dashboard/{original_dashboard_id}"

    
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
    response = requests.post(f"{kibana_host}/api/saved_objects/dashboard/{new_id}", headers=headers,data=json.dumps(payload))

    
    # Check the result of the POST request
    if response.status_code == 200:
        # Parse the response to extract the new dashboard's ID
        new_dashboard_id = response.json()['id']
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
    
    alias_names = request.session.get('data_view_name', None)
    data_view_id = get_data_view_id_by_name(alias_names)
    workspace_name = request.session.get('workspace_name', None)
    if request.method == 'POST':
        dashboard_id = "e0825920-21c5-41ea-a451-e1521233f90f"
        request.session['dashboard_ids'] = dashboard_id
        time.sleep(1)
        create_new_dashboard(dashboard_id,workspace_name,data_view_id)
    return redirect("generate_embed_link")
def generate_embed_link(request):
    fetch_from_elasticsearch(request)
    workspace_name = request.session.get('workspace_name', None)
    print(workspace_name)
    dashboardId = "ca157a96-69f9-4505-be92-9255f1e66d3d"
    print ("Generating embed link")
    
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
    embed_link = f"<iframe src='{kibana_host}/app/dashboards#/view/{dashboardId}{embed_params}' height='600' width='950'></iframe>"

    return render(request, 'generate_embed_link.html', context={'embed_link': embed_link,'link':"192.168.17.101:8000/manage/fetch_data/"})


                                  #  DATA STREAM LIST OF FUNCTIONS



# DATA STREAM LIST OF FUNCTION

# <iframe src="http://192.168.6.175:5601/app/dashboards#/view/e0825920-21c5-41ea-a451-e1521233f90f?embed=true&_g=(refreshInterval%3A(pause%3A!t%2Cvalue%3A60000)%2Ctime%3A(from%3A'2023-01-14T04%3A40%3A59.269Z'%2Cto%3A'2023-01-14T04%3A41%3A21.251Z'))&show-query-input=true&show-time-filter=true" height="600" width="800"></iframe>


   


def display_data_stream_mapping(request,selectedDatabase):
    print("display_data_stream_mapping")
    """
    Displays the entire mapping of the selected data stream's backing indices.

    Parameters:
    - data_stream_name: The name of the selected data stream.
    """
    response = requests.get(f'http://192.168.6.12:9200/_data_stream/{selectedDatabase}')
    if response.status_code == 200:
        data_stream_info = response.json()
        backing_indices = data_stream_info['data_streams'][0].get('indices', [])
        
        if backing_indices:
            # Get the latest (most recent) backing index
            latest_index_name = backing_indices[-1]['index_name']
            print(latest_index_name)
            # Retrieve and display the mapping for the latest backing index
            mapping_response = requests.get(f'http://192.168.6.12:9200/{selectedDatabase}/_mapping')
            datastream_mapping = mapping_response.json()
            import pprint
            pprint.pprint(datastream_mapping)
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



# For data enrichiment
def police_page(request):
    list_indices = list_user_indices()
    
    return render(request,'Enrich_template/Create_police.html',context={
                'list_indices': list_indices,
            })

def search_page(request):
    list_indices = list_user_indices()
    return render(request,'search.html',context={
                'list_indices': list_indices,
            })



def create_police(request):
    global police_name
    if request.method == 'POST':
        police_name = request.POST.get('police_name')
        index_name = request.POST.get('database_type')
        match_field = request.POST.get('match_field')
        columns = request.POST.getlist('columns[]')
        print(police_name)
        print(index_name)
        print(match_field)
        print(columns)
        request.session['police_name'] = police_name
        return redirect("excute_page")

def excute_page(request):
    police_name = request.session.get('police_name', None)
    
    context = {
        'police_name': police_name # Add aliases to context
    }
    return render(request, 'Enrich_template/excute_page.html', context)
def create_excute(request):

    police_name = request.session.get('police_name', None)
    
    return redirect("ingestion_pipeline_page")

def ingestion_pipeline_page(request):
    police_name = request.session.get('police_name', None)
    
    context = {
        'police_name': police_name # Add aliases to context
    }
    return render(request, 'Enrich_template/ingestion_pipeline.html', context)


