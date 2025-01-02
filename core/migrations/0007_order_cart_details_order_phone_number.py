# Generated by Django 5.1.2 on 2025-01-01 17:19

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0006_address_cart_order'),
    ]

    operations = [
        migrations.AddField(
            model_name='order',
            name='cart_details',
            field=models.TextField(default='exit'),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='order',
            name='phone_number',
            field=models.CharField(default='exit', max_length=12),
            preserve_default=False,
        ),
    ]
