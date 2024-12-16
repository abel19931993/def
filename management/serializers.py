from rest_framework import serializers
from django.contrib.auth.models import User
from .models import *
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('id','username','email')

class RegisterSerializer(serializers.ModelSerializer):
    role = serializers.CharField(write_only=True,required=False)
    class Meta:
        model = User
        fields = ('username','email','password','role')
    def create(self,validate_data):
        role_name = validate_data.pop('role',None)
        user = User.objects.create_user(
            validate_data['username'],
            validate_data['email'],
            validate_data['password']
        )
        if role_name:
            role,created = Role.objects.get_or_create(name=role_name)
            UserRole.objects.create(user=user,role=role)
        return user
class LoginSerializer(serializers.Serializer):
    username = serializers.CharField(required=True)
    password = serializers.CharField(required=True, write_only=True)
class ResourceSerializer(serializers.ModelSerializer):
    created_by = serializers.PrimaryKeyRelatedField(read_only=True)
    class Meta:
        model = Resource
        fields = '__all__'
        # fields = ('id','workspace_name','index_name','data_view_id','alias_id','dashboard_id','created_by','created_at','updated_at')
    