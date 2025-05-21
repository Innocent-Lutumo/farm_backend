# # models.py
# from django.db import models
# from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin

# class CustomUserManager(BaseUserManager):
#     def create_user(self, username, email, password=None, **extra_fields):
#         if not username:
#             raise ValueError("The Username field must be set")
#         if not email:
#             raise ValueError("The Email field must be set")

#         email = self.normalize_email(email)
#         user = self.model(username=username, email=email, **extra_fields)
#         user.set_password(password)
#         user.save(using=self._db)
#         return user

#     def create_superuser(self, username, email, password=None, **extra_fields):
#         extra_fields.setdefault("is_staff", True)
#         extra_fields.setdefault("is_superuser", True)
#         extra_fields.setdefault("is_active", True)
#         extra_fields.setdefault("role", "superadmin")
#         return self.create_user(username, email, password, **extra_fields)

# class CustomUser(AbstractBaseUser, PermissionsMixin):
#     ROLE_CHOICES = (
#         ("admin", "Standard Admin"),
#         ("superadmin", "Super Admin"),
#         ("content_admin", "Content Administrator"),
#         ("user_admin", "User Administrator"),
#         ("reporting_admin", "Reporting Administrator"),
#     )

#     username = models.CharField(max_length=150, unique=True)
#     email = models.EmailField(unique=True)
#     full_name = models.CharField(max_length=255)
#     role = models.CharField(max_length=50, choices=ROLE_CHOICES, default="admin")
#     seller_name = models.CharField(max_length=150, blank=True, null=True)
#     seller_residence = models.CharField(max_length=150, blank=True, null=True)
#     is_active = models.BooleanField(default=True)
#     is_staff = models.BooleanField(default=False)
#     date_joined = models.DateTimeField(auto_now_add=True)

#     # Required for admin compatibility
#     groups = models.ManyToManyField(
#         "auth.Group",
#         related_name="custom_user_set",
#         blank=True,
#         verbose_name="groups",
#     )
#     user_permissions = models.ManyToManyField(
#         "auth.Permission",
#         related_name="custom_user_set",
#         blank=True,
#         verbose_name="user permissions",
#     )

#     objects = CustomUserManager()

#     USERNAME_FIELD = "username"
#     REQUIRED_FIELDS = ["email", "full_name"]

#     def __str__(self):
#         return self.username
