# Generated by Django 5.2 on 2025-04-12 10:30

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('myapp', '0002_alter_farmrent_image_alter_farmsale_image'),
    ]

    operations = [
        migrations.AddField(
            model_name='farmrent',
            name='click_count',
            field=models.IntegerField(default=0),
        ),
        migrations.AddField(
            model_name='farmrent',
            name='rent_duration',
            field=models.PositiveIntegerField(default=12),
        ),
        migrations.AddField(
            model_name='farmsale',
            name='click_count',
            field=models.IntegerField(default=0),
        ),
    ]
