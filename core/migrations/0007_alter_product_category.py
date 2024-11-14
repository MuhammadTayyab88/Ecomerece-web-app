# Generated by Django 5.1.2 on 2024-11-06 20:42

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0006_alter_product_category'),
    ]

    operations = [
        migrations.AlterField(
            model_name='product',
            name='category',
            field=models.CharField(choices=[('Electronics', 'Electronics'), ('Fashion', 'Fashion'), ('Bages', 'Bages'), ('Jewellery', 'Jewellery')], default='Fashion', max_length=50),
        ),
    ]
