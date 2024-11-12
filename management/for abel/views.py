
import requests
import csv
import json,copy
from elasticsearch import Elasticsearch
from rest_framework.response import Response

from rest_framework import permissions, status
from django.http import JsonResponse

from rest_framework import status
from django.contrib.auth.hashers import make_password 
import os
from django.conf import settings
from django.core.files.storage import FileSystemStorage
# from django.views.decorators.csrf import ensure_csrf_cookie
# from rest_framework.authtoken.models import Token
# from django.contrib.auth import authenticate, login, logout
# from django.http import HttpResponse, JsonResponse
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
# from django.shortcuts import get_object_or_404
from .serializers import *
from .permissions import *
from .models import *
from rest_framework.decorators import api_view, permission_classes
from rest_framework.views import APIView

from django.shortcuts import render,redirect
from .serializers import *
from rest_framework.permissions import IsAuthenticated

class SystemUserStaffPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        # Check if any of the required permissions are met
        return request.user.is_authenticated and (
           IsAdmin().has_permission(request, view)
        )
    



logstash_input_template = {
"mysql":"""
    input {
    jdbc {
        jdbc_connection_string => "jdbc:mysql://%s"
        jdbc_user => "%s"
        jdbc_password => "%s"
        jdbc_driver_class => "org.postgresql.Driver"
        schedule => "%s" # cronjob schedule format 
        statement => "SELECT * FROM %s" # the PG command for retrieving the documents IMPORTANT: no semicolon!
        jdbc_paging_enabled => "%s"
        jdbc_page_size => "%s"
    }
    }""",

"postgresql": """    
    input {
    jdbc {
        jdbc_connection_string => "jdbc:postgresql://%s"
        jdbc_user => "%s"
        jdbc_password => "%s"
        jdbc_driver_library => "%s"
        jdbc_driver_class => "com.mysql.jdbc.Driver"
        schedule => "%s"  # cronjob schedule format (e.g., "* * * * *")
        statement => "SELECT * FROM %s WHERE updated_at > :sql_last_value"
        use_column_value => "%s"
        tracking_column => "%s"
        tracking_column_type => "%s"
        clean_run => "%s"
    }
    }
    """
}

logstash_output_template={
   "elasticsearch" : """output {
    elasticsearch {
    hosts => ["%s"]
    index => "%s"
    #if enable ssl between elastic and logstash
    #ssl => true 
    ssl_certificate_verification => false 
    #path cert
    #cacert => '' 
    #elastic host
    #hosts => [""] 
    #name your index
    #index => "" 
    user => "%s"   
    password => "%s"   
    }
  }"""
}
test_database_array = [
  [
    "mysql",
    "localhost:3306/my_database",
    "my_user",
    "my_password",
    "at night",
    "cbe table",
    "true","1000"]
    ]
# data view methods
kibana_host = "http://192.168.6.175:5601" 
es_host = "http://192.168.6.175:9200"
headers = {
    'Content-Type': 'application/json',
    'kbn-xsrf': 'true'  # Required header for Kibana API requests
}
def get_index_aliases(index_name):
    """
    Get aliases for a specified Elasticsearch index.

    :param es_host: The Elasticsearch host (e.g., "http://localhost:9200").
    :param index_name: The name of the index to retrieve aliases for.
    :return: A dictionary of aliases for the specified index.
    """
    # Create an Elasticsearch client
    es = Elasticsearch([es_host])

    try:
        # Retrieve aliases for the specified index
        response = es.indices.get_alias(index=index_name)
        aliases = response.get(index_name, {}).get('aliases', {})
        return aliases
    except Exception as e:
        print(f"Error retrieving aliases for index {index_name}: {e}")
        return None
# aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
def get_all_field():
    """
    Get all user-defined aliases for all Elasticsearch indices with all date fields.

    :param es_host: The Elasticsearch host (e.g., "http://localhost:9200").
    :return: A dictionary containing all aliases with their date fields.
    """
    # Create an Elasticsearch client
    es = Elasticsearch([es_host])

    aliases_fields = {}

    try:
        # Retrieve all aliases
        response = es.indices.get_alias()
      
        for index, data in response.items():
            for alias in data['aliases']:

                # Check if the alias is user-defined (not a system alias)
                if not alias.startswith('.'):
                    # Include all fields associated with the alias
                    field_response = es.indices.get_mapping(index=index)
                    fields = field_response[index]['mappings']['properties']
                    
                    # Filter fields to only include those of type 'date'
                    date_fields = {field_name: field_info for field_name, field_info in fields.items() if field_info.get('type') == 'date'}
                    
                    # Store only the field names
                    if date_fields:
                        aliases_fields[alias] = list(date_fields.keys())

        return aliases_fields  # Return a dictionary of aliases with their date field names
    except Exception as e:
        print(f"Error retrieving aliases: {e}")
        return None
# aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa     

def get_all_aliases():
    """
    Get all aliases for all Elasticsearch indices.

    :param es_host: The Elasticsearch host (e.g., "http://localhost:9200").
    :return: A dictionary of all aliases for all indices.
    """
    # Create an Elasticsearch client
    es = Elasticsearch([es_host])

    user_aliases = []

    try:
        # Retrieve all aliases
        response = es.indices.get_alias()

        for index, data in response.items():
            for alias in data['aliases']:
                # Check if the alias is user-defined (not a system alias)
                if not alias.startswith('.'):
                    user_aliases.append(alias)

        return list(set(user_aliases))  # Return unique aliases
    except Exception as e:
        print(f"Error retrieving aliases: {e}")
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
            if not view_info['name'].startswith('.'):
             data_views_info.append(view_info)

        print("Retrieved data views info successfully.")
        return data_views_info
    else:
        print(f"Failed to retrieve data views: {response.status_code} - {response.text}")
        return None

def get_all_dashboards():
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
    # print("responseeeeeeeeeeeeeeeeeeee")
    # print(response)
    # print("responseeeeeeeeeeeeeeeeeeee")
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
    # <iframe src="http://192.168.6.175:5601/app/dashboards#/create?embed=true&_g=(refreshInterval%3A(pause%3A!t%2Cvalue%3A60000)%2Ctime%3A(from%3Anow-15m%2Cto%3Anow))" height="600" width="800"></iframe>

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


def data_view(request):
  
    indexData = get_all_field()
    print(indexData)
    aliases = get_all_aliases()  # Assuming this function returns a list of aliases
    tabss = [{"id": "tab1", "label": "Tab 1"}]
    context = {
        'tabs': tabss,
        'aliases': aliases ,
        'indexData': indexData # Add aliases to context
    }
    return render(request, 'data_view.html', context)


def create_data_view(request):
    data_view_name = request.POST.get('data-view-name')
    indices = request.POST.get('indices')
    time_field_name = request.POST.get('time-field-name')
    create_data_view_(data_view_index_pattern=indices,time_field_name=time_field_name,data_view_name=data_view_name)
    return redirect("data_view")
# dashboard methods
def dashborad(request):
    print(get_all_dashboards())
    data_view = get_data_views()
    tabss = [{"id": "tab1", "label": "Tab 1",}]
    context = { 'tabs':  tabss,"data_view":data_view }
    return render(request,'new_dashboard.html',context)

def create_dashborad(request):
    tabss = [{"id": "tab1"}]
    context = { 'tabs':  tabss }
    if request.method == 'POST':
        dashboard_title = request.POST.get('dashboard-title')
        data_view_id = request.POST.get('data-view-id')
        create_new_dashboard("fdd1775e-7805-49ea-840c-867d3a3d75eb",dashboard_title,data_view_id)
    return redirect("dashborad")

def logstash_input(*args):
  temp = logstash_input_template[args[0]] % (args[1:])
  return temp

def logstash_input_sourceD(input_array):
  input_all=''

  for e in input_array:
    store_logstash_input = logstash_input(*e)
    input_all= store_logstash_input

  return input_all
logstash_mutate_operations = {
    "add_field": """ add_field => { "%s" => "%s" }    """,
    "add_tag": """ add_tag => [ "%s"]    """,
    "remove_field": """ remove_field => [ "%s" ]    """,
    "remove_tag": """ remove_tag => [ "%s" ] """,
    "rename":""" rename => { "%s" => "%s" }    """,
    "replace": """ replace => { "%s" => "%s" }    """,
    "convert": """ convert => { "%s" => "%s" }    """,
    "update": """ update => { "%s" => "%s" }    """,
    "uppercase": """ uppercase => [ "%s" ]    """,
    "lowercase": """ lowercase => [ "%s" ]    """,
    "gsub": """ gsub => ["%s", "[^a-zA-Z0-9]", ""] """,
    "split": """ split => { "%s" => "," }    """,
    "join": """ join => { "%s" => ", " }    """,
    "merge": """ merge => { "%s" => "%s" }    """,
    "copy": """ copy => { "%s" => "%s" }    """,
    "strip": """ strip => [ "%s" ]    """,
    "coerce": """ coerce => { "%s" => 0 }   """,
    "location":""" %s """
}
def return_location(string_x,string_y):
    m1='add_field => { \n "location" => "%{'
    m2='}'
    m3=', %{'
    m4='}"'
    m5=""" convert => { "location" => "float" } """
    z = m1+string_x+m2+m3+string_y+m4+"\n"+m2+"\n"+m5
    return z
def filter_generate(*args):
    test_operation= args[0]
    if test_operation == "location":
        temp=return_location(args[1],args[2])
    
    elif len(args) == 3:
        test_variable = args[1]
        test_variable2 = args[2]
        temp = logstash_mutate_operations[test_operation] % (test_variable, test_variable2)

    elif len(args) == 2:  
        test_variable = args[1]
        temp = logstash_mutate_operations[test_operation] % (test_variable)
    else:
        return "invalid arguments"

    return temp
def all_mutate_strings(myarray):
    # this is a string variable to hold the final value of the config statements
    mutate_array= []
    # this for loop is used for appending generated mutate filter statements to the mutate array
    mutate_array_all = ''
    
    for x in myarray:
        if len(x) == 3:
            store_mutate = filter_generate(*x)
            mutate_array.append(store_mutate)
        elif len(x) == 2:
            store_mutate2 = filter_generate(x[0], x[1])
            mutate_array.append(store_mutate2)
    # print(mutate_array_all)
    # this for loop is used for generating the final mutate filter statement
    for e in mutate_array:
        mutate_array_all = mutate_array_all + "\n" + e
    return mutate_array_all

def index_view(request):
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

def index_view(request):
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
def data_ingestion_page(request):

    tabss = [
    {"id": "tab1", "label": "Tab 1",},
    {"id": "tab2", "label": "Tab 2",},
    {"id": "tab3", "label": "Tab 3", "content": "Content for Tab 3"}
]
    context = {
            'tabs':  tabss
            # Add more context variables as neededS
            }
    return render(request,'Logstash_pipeline\data_ingestion.html',context)



# Step 2: List all user-created indices
def list_user_indices():
    response = requests.get('http://192.168.6.175:9200/_cat/indices?v&h=index&format=json')
    all_indices = response.json()
    user_indices = [index['index'] for index in all_indices if not index['index'].startswith('.')]
    return user_indices


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
def create_workspace(request):
    workspace_name = None
    if request.method == 'POST':
        workspace_name = request.POST.get('workspace_name')
        print(f'Workspace Name: {workspace_name}')  # For debugging purposes

    return render(request, 'filter.html', context={
        'supported_database': list_user_indices(),
        'workspace_name': workspace_name  # Pass the workspace name to the template
    })

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
        
def create_alias(selected_index,filter_body, workspace_name):
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
        else:
            print(f"Failed to create alias. HTTP Status Code: {response.status_code}")
    else:
        print("No filter values provided. Alias creation aborted.")
filters = {}
filter_body =[]
result =[]
workspace_name = ''
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
   
    
    create_alias(index_name, filter_body, workspace_name) 
    return render(request, 'data_view.html', context={
        'supported_database': list_user_indices(),
        'workspace_name': workspace_name
    })

 #TODO put this in setting.py
def data_add(request):
        col_name_data = []
        convert_data = []
        gsub_data = []
        rename_data = []
        type_data = []
        non_repeater_fields = {
            'database': None,
            'con_string':None,
            'user': None,
            'pass':None,
            'schedule': None,
            'statment': None,
            'jdbc_paging': None,
            'jdbc_page_size':None,
            'elastic_hosts':None,
            'elastic_index': None,
            'elastic_user': None,
            'elastic_pass': None,
        }
        for key, value in request.POST.items():
           
            if key.startswith('outer-group['):
                outer_index = int(key.split('[')[1].split(']')[0])
                if key.startswith(f'outer-group[{outer_index}][inner-group]'):
                    inner_index = int(key.split('[')[3].split(']')[0]) 
                   
                    if 'col_name' in key:
                        if len(col_name_data) <= inner_index:
                            col_name_data.append({})
                        col_name_data[inner_index] = value
                        print(value)
                    if 'convert' in key:
                        if len(convert_data) <= inner_index:
                            convert_data.append({})
                        convert_data[inner_index] = value
                        print(value)
                    if 'gsub' in key:
                        if len(gsub_data) <= inner_index:
                            gsub_data.append({})
                        gsub_data[inner_index] = value
                        print(value)
                    if 'rename' in key:
                        if len(rename_data) <= inner_index:
                            rename_data.append({})
                        rename_data[inner_index] = value
                    if 'type' in key:
                        if len(type_data) <= inner_index:
                            type_data.append({})
                        type_data[inner_index] = value
                    

                  
            else:
                    for field in non_repeater_fields:
                        if field in key:
                            non_repeater_fields[field] = value
                            
                           
     
        # input part
        database_type = non_repeater_fields["database"]
        con_string = non_repeater_fields["con_string"]
        user =non_repeater_fields["user"]
        password =non_repeater_fields["pass"]
        schedule =non_repeater_fields["schedule"]
        statement = non_repeater_fields["statment"]
        jdbc_paging = non_repeater_fields["jdbc_paging"]
        jdbc_page = non_repeater_fields["jdbc_page_size"]
        test_database_array = [
                [
                    database_type,
                    con_string,
                    user,
                    password,
                    schedule,
                    statement,
                    jdbc_paging,
                    jdbc_page
                  
                    ]
        ]
       
        print(logstash_input_sourceD(test_database_array))

        # filter part

        array_2d = []
        for col_name_item, convert_item, gsub_item, rename_item,type_data in zip(col_name_data, convert_data, gsub_data, rename_data,type_data):
      
            if col_name_item:  
                if convert_item:  
                    array_2d.append(["convert", col_name_item, convert_item])
                if rename_item: 
                    array_2d.append(["rename", col_name_item, rename_item])
                if gsub_item == 'true':  
                    array_2d.append(["gsub", col_name_item])
        print( all_mutate_strings(array_2d))

        # output part

        hosts_name = non_repeater_fields["elastic_hosts"]
        index_name = non_repeater_fields["elastic_index"]
        elastic_user =non_repeater_fields["elastic_user"]
        elastic_password =non_repeater_fields["elastic_pass"]
        return render(request, 'Logstash_pipeline/data_ingestion.html', context={'supported_database': supported_datebase})


def generate_embed_link(request, dashboard_id, base_url=kibana_host):
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
    embed_params = "?embed=true&_g=(refreshInterval%3A(pause%3A!t%2Cvalue%3A0)%2Ctime%3A(from%3Anow-1y%2Fd%2Cto%3Anow))&show-query-input=true&show-time-filter=true"
    embed_link = f"<iframe src='{base_url}/{dashboard_id}{embed_params}' height='600' width='800'></iframe>"

    return render(request, 'Logstash_pipeline/embeded_dashboard.html', context={'embed_link': embed_link})



kibana_host = "http://192.168.6.175:5601"
template_dashboard_id = "your_template_dashboard_id"  # Replace with the actual template dashboard ID
new_dashboard_title = "My New Dashboard"
new_data_view_id = "your_new_data_view_id"  # Replace with the actual data view ID
auth = ('username', 'password')  