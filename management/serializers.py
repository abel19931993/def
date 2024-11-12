from rest_framework import serializers
from .models import *
from django.contrib.auth import get_user_model, authenticate
from django.core.files.base import ContentFile
from rest_framework.relations import PrimaryKeyRelatedField

   
class SystemUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = SystemUser
        fields = "__all__"
    
class First_requestSerializer(serializers.ModelSerializer):
    request_subited_person = serializers.PrimaryKeyRelatedField(many=True, read_only=True)
    class Meta:
        model = First_request
        fields = "__all__"

class UnitSerializer(serializers.ModelSerializer):
     class Meta:
        model = Unit
        fields = "__all__"

class targetSerializer(serializers.ModelSerializer):
    class Meta:
        model = Target
        fields = "__all__"
        
class caseSerializer(serializers.ModelSerializer):
    class Meta:
        model = Case
        fields = "__all__"

class subcasesSerializer(serializers.ModelSerializer):
    class Meta:
        model = subCase
        fields = "__all__"

class ResultSerializer(serializers.ModelSerializer):
    class Meta:
        model = OperationResult
        fields = "__all__"

class AssignSerializer(serializers.ModelSerializer):
    class Meta:
        model = Assign
        fields = "__all__"


# # Serializer for phone_number items
# class PhoneNumberSerializer(serializers.Serializer):
#     phone = serializers.CharField(required=True)
#     imei = serializers.CharField(required=True)
# class CarSerializer(serializers.Serializer):
#     model = serializers.CharField(required=True)
#     plate_number = serializers.CharField(required=True)
# class subcaseSerializer(serializers.ModelSerializer):
#     result_list = serializers.ListField(child=ResultListSerializer())
#     phone_number = serializers.ListField(child=PhoneNumberSerializer())
#     car_info =  serializers.ListField(child=CarSerializer())
#     class Meta:
#         model = Sub_casee
#         fields = '__all__'
#     def fetch_case_name(self, case_id):
#         # Define your API URL for fetching case names
#         api_url = f'http://127.0.0.1:8000/case/{case_id}'

#         try:
#             response = requests.get(api_url)
#             response.raise_for_status()  # Raise HTTPError for bad responses
#             response_data = response.json()
#             return response_data.get('case_name')  # Assume 'name' is the key for the case name
#         except requests.RequestException as e:
#             print(f"Error fetching case name: {e}")
#             return None
#     def fetch_subcase_name(self, subcase_id):
#         # Define your API URL for fetching case names
#         api_url = f'http://127.0.0.1:8000/subcasee/{subcase_id}'

#         try:
#             response = requests.get(api_url)
#             response.raise_for_status()  # Raise HTTPError for bad responses
#             response_data = response.json()
#             return response_data.get('sub_case')  # Assume 'name' is the key for the case name
#         except requests.RequestException as e:
#             print(f"Error fetching subcase: {e}")
#             return None
#     def fetch_unit_name(self, unit_id):
#         # Define your API URL for fetching case names
#         api_url = f'http://127.0.0.1:8000/unit/{unit_id}'

#         try:
#             response = requests.get(api_url)
#             response.raise_for_status()  # Raise HTTPError for bad responses
#             response_data = response.json()
#             return response_data.get('unit')  # Assume 'name' is the key for the case name
#         except requests.RequestException as e:
#             print(f"Error fetching unit: {e}")
#             return None
#     def to_internal_value(self, data):
#     # Initialize the list to store dictionaries for each form entry
#       result_list_data = []
#       phone_number_data = []
#       car_data = []

#     # Define the expected field names for result_list and phone_number
#       result_list_fields = ['case_name', 'subcase','sub_subcase', 'unit', 'value']
#       phone_number_fields = ['phone', 'imei']
#       car_fields = ['model', 'plate_number']
     
#     # Initialize variables for non-repeater fields
#       non_repeater_fields = {
#         'end_date': None,
#         'name': None,
#         'house_number': None,
#         'target_location': None,
#         'description': None,
#         'profile_picture': None,
#         'target_provider_person': None,
#         'target_accepter_company': None,
#         'target_provider_company': None,
#         'target_accepter_person': None
#     }

#     # Track the current form entry index for each list
#       result_index = -1
#       phone_index = -1
#       car_index = -1
#       current_result_entry = {field: None for field in result_list_fields}
#       current_phone_entry = {field: None for field in phone_number_fields}
#       current_car_entry = {field: None for field in car_fields}
#     # Iterate over the provided data
#       for key, value in data.items():
#         # Debugging: Print the key-value pairs being processed
#         print(f"Processing key: {key}, value: {value}")

#         # Handle repeater fields
#         if '[' in key and ']' in key:
#             try:
#                 # Extract the indices from the key
#                 parts = key.split('[')
#                 outer_index = int(parts[1].split(']')[0])
#                 inner_index = int(parts[3].split(']')[0])
#                 index = (outer_index, inner_index)

#                 # Detect if we are processing a new result_list entry
#                 if index != result_index:
#                     if any(current_result_entry.values()):
#                         result_list_data.append(current_result_entry)
#                         print(f"Appended to result_list_data: {current_result_entry}")
#                     current_result_entry = {field: None for field in result_list_fields}
#                     result_index = index

#                 # Detect if we are processing a new phone_number entry
#                 if inner_index != phone_index:
#                     if any(current_phone_entry.values()):
#                         phone_number_data.append(current_phone_entry)
#                         print(f"Appended to phone_number_data: {current_phone_entry}")
#                     current_phone_entry = {field: None for field in phone_number_fields}
#                     phone_index = inner_index
#                 if inner_index != car_index:
#                     if any(current_car_entry.values()):
#                         car_data.append(current_car_entry)
                       
#                     current_car_entry = {field: None for field in car_fields}
#                     car_index = inner_index

#                 # Check if the key corresponds to a result_list or phone_number field name for the current entry
#                 for fieldd in result_list_fields:
#                     if f'[{fieldd}]' in key:
#                         if fieldd =='case_name':
#                          current_result_entry['case_name'] = self.fetch_case_name(value)
#                         if fieldd =='subcase':
#                          current_result_entry['subcase'] = self.fetch_subcase_name(value)
#                         if fieldd =='unit':
#                          current_result_entry['unit'] = self.fetch_unit_name(value)
#                         if fieldd =='value':
#                          current_result_entry['value'] = value
#                         if fieldd =='sub_subcase':
#                          current_result_entry['sub_subcase'] = value


#                 for field in phone_number_fields:
#                     if f'[{field}]' in key:
#                         current_phone_entry[field] = value
#                 for fields in car_fields:
#                     if f'[{fields}]' in key:
#                         current_car_entry[fields] = value

#             except (ValueError, IndexError) as e:
#                 print(f"Error extracting index from key: {key}, {e}")
#                 continue

#         # Handle non-repeater fields
#         elif key in non_repeater_fields:
#             non_repeater_fields[key] = value
#             print("Captured non-repeater field: {key} = {value}")

#     # Append the last entries if they contain data
#       if any(current_result_entry.values()):
#         result_list_data.append(current_result_entry)
#         print(f"Final append to result_list_data: {current_result_entry}")

#       if any(current_phone_entry.values()):
#         phone_number_data.append(current_phone_entry)
#         print(f"Final append to phone_number_data: {current_phone_entry}")
#       if any(current_car_entry.values()):
#         car_data.append(current_car_entry)
       

#     # Debugging: Print the final lists before returning
#       print(f"Final result_list_data: {result_list_data}")
#       print(f"Final phone_number_data: {phone_number_data}")

#     # Return the full data with name, age, and non-repeater fields included
#       return {
#         'result_list': result_list_data,
#         'phone_number': phone_number_data,
#         'car_info': car_data,
#         **non_repeater_fields
#     }


#     def create(self, validated_data):
#         # Create the model instance with the mapped data
#          return super().create(validated_data)
