from django.db import models

class FarmSale(models.Model):
    size = models.CharField(max_length=100)
    price = models.DecimalField(max_digits=10, decimal_places=2)
    quality = models.CharField(max_length=100)
    location = models.CharField(max_length=255)
    email = models.EmailField()
    description = models.TextField()
    phone = models.CharField(max_length=15)
    image = models.FileField(upload_to="farm_images/")
    farm_type = models.CharField(max_length=4, default="Sale")

    def __str__(self):
        return f"Farm for Sale - {self.location}"

class FarmRent(models.Model):
    size = models.CharField(max_length=100)
    price = models.DecimalField(max_digits=10, decimal_places=2)
    quality = models.CharField(max_length=100)
    location = models.CharField(max_length=255)
    email = models.EmailField()
    description = models.TextField()
    phone = models.CharField(max_length=15)
    image = models.FileField(upload_to="farm_images/")
    farm_type = models.CharField(max_length=4, default="Rent")

    def __str__(self):
        return f"Farm for Rent - {self.location}"
