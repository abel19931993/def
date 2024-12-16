# from django import forms
# from django.contrib.auth.models import User
# from .models import UserProfile, Role
# class UserRegistrationForm(forms.ModelForm):
#     password = forms.CharField(widget=forms.PasswordInput)
#     role = forms.ModelChoiceField(queryset=Role.objects.all(), required=True)

#     class Meta:
#         model = User
#         fields = ['username', 'email', 'password']

#     def save(self, commit=True):
#         user = super().save(commit=False)
#         user.set_password(self.cleaned_data['password'])
#         if commit:
#             user.save()
#             role = self.cleaned_data['role']
#             UserProfile.objects.create(user=user, role=role)
#         return user

       





