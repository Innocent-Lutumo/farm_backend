from django.db import models

class FarmSale(models.Model):
    size = models.CharField(max_length=100)
    price = models.DecimalField(max_digits=10, decimal_places=2)
    quality = models.CharField(max_length=100)
    location = models.CharField(max_length=255)
    email = models.EmailField()
    description = models.TextField()
    phone = models.CharField(max_length=15)
    farm_type = models.CharField(max_length=4, default="Sale")
    click_count = models.IntegerField(default=0)

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
    farm_type = models.CharField(max_length=4, default="Rent")
    rent_duration = models.CharField(max_length=100, null=True, blank=True)
    click_count = models.IntegerField(default=0)

    def __str__(self):
        return f"Farm for Rent - {self.location}"
    

class FarmRentTransaction(models.Model):
    STATUS_CHOICES = [
        ('Pending', 'Pending'),
        ('Confirmed', 'Confirmed'),
        ('Cancelled', 'Cancelled'),
    ]

    farm = models.ForeignKey(FarmRent, on_delete=models.CASCADE)
    transaction_id = models.CharField(max_length=100, unique=True)
    renter_email = models.EmailField()
    renter_phone = models.CharField(max_length=20, blank=True, null=True)
    full_name = models.CharField(max_length=100, blank=True, null=True)  
    residence = models.CharField(max_length=100, blank=True, null=True)  
    national_id = models.CharField(max_length=50, blank=True, null=True)  
    rent_date = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='Pending')

    def __str__(self):
        return f"Transaction {self.transaction_id} - {self.farm.location}"
    
class FarmSaleTransaction(models.Model):
    STATUS_CHOICES = [
        ('Pending', 'Pending'),
        ('Confirmed', 'Confirmed'),
        ('Cancelled', 'Cancelled'),
    ]

    farm = models.ForeignKey(FarmSale, on_delete=models.CASCADE)
    transaction_id = models.CharField(max_length=100, unique=True)
    buyer_email = models.EmailField()
    full_name = models.CharField(max_length=255, blank=True, null=True)
    address = models.TextField(blank=True, null=True)
    contact_info = models.CharField(max_length=100, blank=True, null=True)
    national_id = models.CharField(max_length=100, blank=True, null=True)
    intended_use = models.TextField(blank=True, null=True)
    buyer_date = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='Pending')

    def __str__(self):
        return f"Transaction {self.transaction_id} - {self.farm.location}"  
    
class FarmImage(models.Model):
    image = models.ImageField(upload_to='farm_images/')
    farm_sale = models.ForeignKey(FarmSale, on_delete=models.CASCADE, related_name='images', null=True, blank=True)
    farm_rent = models.ForeignKey(FarmRent, on_delete=models.CASCADE, related_name='images', null=True, blank=True)

    def __str__(self):
        if self.farm_sale:
            return f"Image for Sale Farm ID {self.farm_sale.id}"
        if self.farm_rent:
            return f"Image for Rent Farm ID {self.farm_rent.id}"
        return "Unassigned Farm Image"



    

