# Generated by Django 5.2.1 on 2025-05-25 17:40

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('myapp', '0005_alter_farmrent_farm_number_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='farmrent',
            name='farm_number',
            field=models.CharField(default='UNKNOWN', max_length=100),
        ),
        migrations.AlterField(
            model_name='farmsale',
            name='farm_number',
            field=models.CharField(default='UNKNOWN', max_length=100),
        ),
    ]
