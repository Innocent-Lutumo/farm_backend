from django.db import models
from django.contrib.auth.models import User, AbstractUser
from .utils import some_user_function
from django.utils.timezone import now


def get_default_user():
    # Function to get a default user (first admin or create one)
    user = User.objects.filter(is_superuser=True).first()
    if not user:
        user = User.objects.create_user('default', 'default@example.com', 'defaultpassword')
    return user.id


class User(AbstractUser):
    seller_name = models.CharField(max_length=150)
    seller_residence = models.CharField(max_length=150)
    
    # Add related_name attributes to resolve the conflict
    groups = models.ManyToManyField(
        'auth.Group',
        related_name='myapp_user_set', 
        blank=True,
        help_text='The groups this user belongs to.',
        verbose_name='groups',
    )
    user_permissions = models.ManyToManyField(
        'auth.Permission',
        related_name='myapp_user_set',  
        blank=True,
        help_text='Specific permissions for this user.',
        verbose_name='user permissions',
    )


class FarmSale(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, default=get_default_user)
    size = models.CharField(max_length=100)
    price = models.DecimalField(max_digits=10, decimal_places=2)
    quality = models.CharField(max_length=100)
    location = models.CharField(max_length=255)
    email = models.EmailField()
    description = models.TextField()
    phone = models.CharField(max_length=15)
    farm_type = models.CharField(max_length=4, default="Sale")
    is_sold = models.BooleanField(default=False)
    farm_number = models.CharField(max_length=100, blank=False, default='N/A') 
    passport = models.ImageField(upload_to='passports/', blank=False, default='N/A')  
    ownership_certificate = models.ImageField(upload_to='certificates/', blank=True, null=True) 
    click_count = models.IntegerField(default=0)
    
    # Validation fields
    is_validated = models.BooleanField(default=False)
    is_rejected = models.BooleanField(default=False)
    admin_feedback = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(default=now)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"Farm in {self.location} by {self.user.username}"

class FarmRent(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, default=get_default_user)
    size = models.CharField(max_length=100)
    price = models.DecimalField(max_digits=10, decimal_places=2)
    quality = models.CharField(max_length=100)
    location = models.CharField(max_length=255)
    email = models.EmailField()
    description = models.TextField()
    phone = models.CharField(max_length=15)
    farm_type = models.CharField(max_length=4, default="Rent")
    rent_duration = models.CharField(max_length=100, null=True, blank=True)
    is_rented = models.BooleanField(default=False)
    farm_number = models.CharField(max_length=100, blank=False, default='N/A')
    passport = models.ImageField(upload_to='passports/', blank=False, default='N/A')  
    ownership_certificate = models.ImageField(upload_to='certificates/', blank=True, null=True) 
    click_count = models.IntegerField(default=0)
    
    # Validation fields
    is_validated = models.BooleanField(default=False)
    is_rejected = models.BooleanField(default=False)
    admin_feedback = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(default=now)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"Farm in {self.location} by {self.user.username}"

class FarmImage(models.Model):
    farm_sale = models.ForeignKey(
        FarmSale,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="images"
    )
    farm_rent = models.ForeignKey(
        FarmRent,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="images"
    )
    image = models.ImageField(upload_to='farm_images/')
    uploaded_at = models.DateTimeField(null=True, blank=True) 

    def __str__(self):
        if self.farm_sale:
            return f"Image for Sale Farm {self.farm_sale.farm_number}"
        elif self.farm_rent:
            return f"Image for Rent Farm {self.farm_rent.farm_number}"
        return "Unlinked Farm Image"

class FarmRentTransaction(models.Model):
    STATUS_CHOICES = [
        ('Pending', 'Pending'),
        ('Confirmed', 'Confirmed'),
        ('Cancelled', 'Cancelled'),
    ]
    is_validated = models.BooleanField(default=False)
    is_rejected = models.BooleanField(default=False)
    admin_feedback = models.TextField(blank=True, null=True)
    farm = models.ForeignKey(FarmRent, on_delete=models.CASCADE)
    user = models.ForeignKey(User, on_delete=models.CASCADE, default=some_user_function)
    transaction_id = models.CharField(max_length=100, unique=True)
    renter_email = models.EmailField()
    renter_phone = models.CharField(max_length=20, blank=True, null=True)
    full_name = models.CharField(max_length=100, blank=True, null=True)  
    residence = models.CharField(max_length=100, blank=True, null=True)  
    national_id = models.CharField(max_length=50, blank=True, null=True)  
    is_rented = models.BooleanField(default=False) 
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
    is_rented = models.BooleanField(default=False) 
    buyer_date = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='Pending')

    def __str__(self):
        return f"Transaction {self.transaction_id} - {self.farm.location}"  
    

class RentalAgreement(models.Model):
    # Agreement identification
    agreement_id = models.CharField(max_length=100, unique=True)
    farm_id = models.IntegerField()
    transaction_id = models.IntegerField()
    
    # Parties information
    landlord_name = models.CharField(max_length=200)
    landlord_phone = models.CharField(max_length=20)
    landlord_email = models.EmailField()
    landlord_residence = models.TextField()
    landlord_passport = models.TextField(null=True, blank=True) 
    
    tenant_name = models.CharField(max_length=200)
    tenant_phone = models.CharField(max_length=20)
    tenant_email = models.EmailField()
    tenant_residence = models.TextField()
    tenant_passport = models.TextField(null=True, blank=True)
    
    # Farm details
    farm_location = models.CharField(max_length=200)
    farm_size = models.DecimalField(max_digits=10, decimal_places=2)
    farm_quality = models.CharField(max_length=100)
    farm_type = models.CharField(max_length=100)
    farm_description = models.TextField(blank=True)
    
    # Financial terms
    monthly_rent = models.DecimalField(max_digits=12, decimal_places=2)
    security_deposit = models.DecimalField(max_digits=12, decimal_places=2)
    advance_payment = models.DecimalField(max_digits=12, decimal_places=2)
    
    # Agreement details
    agreement_date = models.DateTimeField()
    duration_months = models.IntegerField(default=12)
    
    # Status and tracking
    status = models.CharField(max_length=20, choices=[
        ('draft', 'Draft'),
        ('active', 'Active'),
        ('expired', 'Expired'),
        ('terminated', 'Terminated')
    ], default='active')
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    # PDF file storage
    pdf_file = models.FileField(upload_to='rental_agreements/', null=True, blank=True)
    
    class Meta:
        db_table = 'rental_agreements'
    

