# Generated by Django 5.1.2 on 2024-11-06 15:28

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0004_checkout_dispatched_checkout_verify_order_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='checkout',
            name='status',
            field=models.CharField(choices=[('pending', 'Pending'), ('processed', 'Processed'), ('shipped', 'Shipped'), ('delivered', 'Delivered')], default='pending', max_length=20),
        ),
    ]
