import requests
import json,copy
from elasticsearch import Elasticsearch


# Kibana server details
kibana_host = "http://localhost:5601" 
es_host = "http://localhost:9200"
headers = {
    'Content-Type': 'application/json',
    'kbn-xsrf': 'true'  # Required header for Kibana API requests
}


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

# Example usage
kibana_host = "http://localhost:5601"
template_dashboard_id = "your_template_dashboard_id"  # Replace with the actual template dashboard ID
new_dashboard_title = "My New Dashboard"
new_data_view_id = "your_new_data_view_id"  # Replace with the actual data view ID
auth = ('username', 'password')  # Optional authentication