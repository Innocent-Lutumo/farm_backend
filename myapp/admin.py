from django.contrib import admin
from .models import User, FarmSale, FarmRent, FarmImage, FarmRentTransaction, FarmSaleTransaction
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin

# Register your models here.
admin.site.register(User, BaseUserAdmin)
admin.site.register(FarmImage)
admin.site.register(FarmRent)
admin.site.register(FarmSale)
admin.site.register(FarmRentTransaction)
admin.site.register(FarmSaleTransaction)
