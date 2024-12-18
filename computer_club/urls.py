"""
URL configuration for computer_club project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path,include
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include('user.urls')),
    path('executive/', include('executive.urls')),
    path('post/', include('post.urls')),
    path('event/', include('event.urls')),
    path('activity/', include('activity.urls')),
    path('alumni/', include('alumni.urls')),
    path('vote/', include('election.urls')),
    path('mentor/',include('mentor.urls')),
    path('message/',include('message.urls')),
    path('contact-us/',include('contact_us.urls')),
    
    
    path('api/auth/',include('rest_framework.urls')),
]

urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)