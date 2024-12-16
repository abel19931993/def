from rest_framework import serializers
from django.contrib.auth.models import User
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('id','username','email')

class RegisterSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('username','email','password')
    def create(self,validate_data):
        user = User.object.create_user(
            validate_data['username'],
            validate_data['email'],
            validate_data['password']
        )
        return user