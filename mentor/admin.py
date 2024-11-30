from django.contrib import admin
from .models import Mentor


class MentorAdmin(admin.ModelAdmin):
    list_display = ('name', 'designation', 'email', 'phone', 'expertise','linkedIn_id')  # Fields to display in the list view
    search_fields = ('name', 'email', 'designation')  # Fields that can be searched
    list_filter = ('designation', 'expertise')  # Filters to use on the list view

    # Optional: You can also customize the form to be displayed when adding or editing a mentor
    fields = ('name', 'designation', 'expertise', 'email', 'phone', 'photo', 'bio', 'linkedIn_id')  # Form fields to display
    

admin.site.register(Mentor,MentorAdmin)