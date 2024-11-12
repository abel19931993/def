from django import forms #forms.py
class UploadFileForm(forms.Form):
    file = forms.FileField()

def upload_file(request): #views.py
    if request.method == "POST":
        form = UploadFileForm(request.POST, request.FILES)
        if form.is_valid():
            pass
    return render(request, 'upload_csv.html', {'form': form})


import os #setting

MEDIA_URL = '/media/'
MEDIA_ROOT = os.path.join(BASE_DIR, 'media')

#urls #proper import
urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)