from django.shortcuts import redirect, render
from django.contrib.auth.models import User
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.core.mail import send_mail, EmailMessage
from django.template.loader import render_to_string
from django.contrib.sites.shortcuts import get_current_site
from . tokens import generate_token
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes
from django.contrib.auth.tokens import default_token_generator
from django.urls import reverse
from django.contrib.auth.hashers import make_password
import stripe
from django.conf import settings
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.hashers import make_password
from django.core.mail import send_mail
from django.core.paginator import Paginator
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_POST
from django.db.models import Sum, F
from .models import Cart
from .models import *
import uuid
from django.core.mail import EmailMultiAlternatives
from django.utils.html import strip_tags
stripe.api_key = settings.STRIPE_SECRET_KEY


TWILIO_ACCOUNT_SID = settings.TWILIO_ACCOUNT_SID
TWILIO_AUTH_TOKEN = settings.TWILIO_AUTH_TOKEN


def auth_view(request, type):
    if request.user.is_authenticated:
        return redirect('home') 
    if type == 'signup':
        return render(request, "components/auth.html", {'form_type': 'signup'})
    else:
        return render(request, "components/auth.html", {'form_type': 'login'})


def signup_view(request):
    if request.user.is_authenticated:
        return redirect('home') 
    if request.method == "POST":
        username = request.POST.get("username", None)
        password1 = request.POST.get("password1", None)
        email = request.POST.get("email", None)

        if User.objects.filter(username=username).exists():
            messages.error(request, "Username already exist! Please try some other username.")
            return redirect('signup')
        
        if User.objects.filter(email=email).exists():
            messages.error(request, "Email Already Registered!!")
            return redirect('signup')
        
        if len(username)>20:
            messages.error(request, "Username must be under 20 charcters!!")
            return redirect('signup')
        
        if not username.isalnum():
            messages.error(request, "Username must be Alpha-Numeric!!")
            return redirect('signup')
        
        user = User.objects.create_user(username, email, password1)
        user.is_active = True
        user.save()
        messages.success(request, "Your account has been successfully created")
        return redirect('login')
    else:
        return render(request, "components/auth.html", {'form_type': 'signup'})


def login_view(request):
    if request.user.is_authenticated:
        return redirect('home') 
    if request.method == "POST":
        username = request.POST.get('user-login', None)
        password = request.POST.get('password', None)
        if not username or not password:
            messages.error(request, "Credentials are not provided!")
            return redirect('login')
        user = authenticate(username=username, password=password)
        if user is not None:
            login(request, user)
            messages.success(request, "Login Successfully!")
            return redirect('login')
        else:
            messages.error(request, "Bad Credentials!")
            return redirect('login')
    return render(request, "components/auth.html", {'form_type': 'login'})


def signout(request):
    logout(request)
    messages.success(request, "Logged Out Successfully!")
    return redirect('home')


def forgot(request):
    if request.method == "POST":
        email = request.POST.get('pass-forgot')

        if email:
            try:
                user = User.objects.get(email=email)

                uid = urlsafe_base64_encode(force_bytes(user.pk))
                token = default_token_generator.make_token(user)
                current_site = get_current_site(request)
                reset_url = reverse('change', kwargs={'uidb64': uid, 'token': token})
                reset_link = f'http://{current_site.domain}{reset_url}'

                mail_subject = 'Password Reset'
                # Render the HTML email template
                html_content = render_to_string('components/reset_password_email.html', {
                    'user': user,
                    'reset_link': reset_link,
                })
                # Strip tags for plain-text fallback
                plain_message = strip_tags(html_content)

                # Send email using EmailMultiAlternatives
                email = EmailMultiAlternatives(
                    subject=mail_subject,
                    body=plain_message,
                    from_email='your-email@example.com',
                    to=[user.email]
                )
                email.attach_alternative(html_content, "text/html")
                email.send()

                messages.success(request, "The password reset email has been sent successfully.")
                return redirect('home')

            except User.DoesNotExist:
                messages.error(request, "Sorry, the user with this email address is not registered.")
                return redirect('forget')
        else:
            messages.error(request, "Please try to enter a valid email address next time.")
            return redirect('forget')

    return render(request, "components/auth.html", {"form_type": "forget"})


def change(request, uidb64, token):
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = User.objects.get(pk=uid)
        if default_token_generator.check_token(user, token):
            if request.method == "POST":
                password1 = request.POST.get('password1')
                password2 = request.POST.get('password2')

                if password1 and password2 and password1 == password2:
                    user.password = make_password(password1)
                    user.save()
                    messages.success(request, f"Password changed successfully for user: {user.username}")
                    return redirect('home')
                else:
                    messages.error(request, "Passwords do not match or some fields are empty. Please try again.")
                    return redirect('home')
            else:
                return render(request, "components/auth.html", {'user': user, 'uidb64': uidb64, 'token': token, "form_type": "change"})
        else:
            messages.error(request, "The password reset link is no longer valid.")
            return redirect('home')
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        messages.error(request, "The password reset link is no longer valid.")
        return redirect('home')


def activate(request, uidb64, token):
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        myuser = User.objects.get(pk=uid)
    except (TypeError,ValueError,OverflowError,User.DoesNotExist):
        myuser = None

    if myuser is not None and generate_token.check_token(myuser,token):
        myuser.is_active = True
        myuser.save() 
        login(request,myuser) 
        messages.success(request, "Your Account has been activated!")
        username = myuser.username
        return render('login')
    else:
        return render(request,'components/change_password.html')


def landing_page_view(request):
    return render(request, "components/landing-page.html")

@login_required(login_url='/auth/login/')
def products_view(request, category):
    categories = SubCategory.objects.filter(main_category__name=category)
    products = Product.objects.filter(
        sub_category__main_category__name=category
    ).order_by("-created_at")

    paginator = Paginator(products, 12)
    page_number = request.GET.get("page")
    page_products = paginator.get_page(page_number)

    context = {
        "products": page_products,
        "categories": categories,
        "requested_category": category,
    }
    return render(request, "components/products.html", context)

@login_required(login_url='/auth/login/')
def filter_products_view(request, category, sub):
    categories = SubCategory.objects.filter(main_category__name=category)
    products = Product.objects.filter(sub_category__name=sub).order_by("-created_at")

    paginator = Paginator(products, 12)
    page_number = request.GET.get("page")
    page_products = paginator.get_page(page_number)

    context = {
        "products": page_products,
        "categories": categories,
        "requested_category": category,
        "selected_sub_category": sub,
    }
    return render(request, "components/products.html", context)

@login_required(login_url='/auth/login/')
def product_detail_view(request, pk):
    product = Product.objects.get(id=pk)
    context = {"product": product}
    return render(request, "components/single-product.html", context)


@login_required(login_url='/auth/login/')
def add_cart_view(request, pk, quantity):
    product = Product.objects.get(id=pk)
    cart  = Cart.objects.get_or_create(
        user=request.user,
        product = product,
    )[0]
    cart.quantity =  quantity
    cart.save()
    messages.success(request, "Product added to cart")
    return redirect('user_cart')


@login_required(login_url='/auth/login/')
def cart_view(request):
    cart_items = Cart.objects.filter(user=request.user)
    if not cart_items:
        messages.error(request, "Cart is empty, Add products to cart to view")
        return redirect("home")
    delivery_charges = 200
    total_product_price = cart_items.aggregate(
        total=Sum(F('quantity') * F('product__sale_price'))
    )['total'] or 0 
    total_price = delivery_charges + total_product_price
    context = {
        "cart_items": cart_items,
        "cart_items_count": cart_items.count(),
        "delivery_charges": delivery_charges,
        "total_product_price": total_product_price,
        "total_price": total_price,
    }
    return render(request, "components/cart.html", context)

@login_required(login_url='/auth/login/')
def remove_from_cart(request, item_id):
    if request.method == 'POST':
        try:
            cart_item = get_object_or_404(Cart, id=item_id, user=request.user)
            cart_item.delete()  # Delete the item from the cart
            messages.success(request, "Item removed from cart!")
            return redirect('user_cart')  # Replace 'cart' with your actual URL name if needed
        except Cart.DoesNotExist:
            messages.error(request, "Failed to remove item from cart.")
            return redirect('home')  # Adjust as needed for your flow
    return redirect('home')  # Adjust as needed

@login_required(login_url='/auth/login/')
def order_view(request):
    if request.method == "POST":
        phone_number = request.POST.get("phone_number")
        address_line1 = request.POST.get("address_line1")
        city = request.POST.get("city")
        state = request.POST.get("state")
        postal_code = request.POST.get("postal_code")
        user = request.user

        if phone_number and address_line1 and city and state and postal_code:
            # Create a new address
            address = Address.objects.create(
                user=user,
                phone_number=phone_number,
                address_line1=address_line1,
                city=city,
                state=state,
                postal_code=postal_code,
                address_type="shipping",
            )

            # Calculate total price
            cart_items = Cart.objects.filter(user=user)
            total_product_price = cart_items.aggregate(
                total=Sum(F('quantity') * F('product__sale_price'))
            )['total'] or 0

            # Create a new order
            order = Order.objects.create(
                user=user,
                shipping_address=address,
                billing_address=address,
                total_amount=total_product_price + 200,  # Adding shipping charges
                transaction_id=str(uuid.uuid4().int)[:5],
            )

            # Clear the cart
            cart_items.delete()

            # Generate email content
            mail_subject = "Order Confirmation"
            reset_link = f"http://{request.get_host()}/orders/{order.id}/"
            html_content = render_to_string('base/order_confirmation_email.html', {
                'user': user,
                'order': order,
                'reset_link': reset_link,
            })
            plain_message = strip_tags(html_content)

            # Send email using EmailMultiAlternatives
            email = EmailMultiAlternatives(
                subject=mail_subject,
                body=plain_message,
                from_email='iqcollectionsstore@gmail.com',
                to=[user.email]
            )
            email.attach_alternative(html_content, "text/html")
            email.send()

            messages.success(request, "Order placed successfully. A confirmation email has been sent.")
            return redirect("user_cart")
        else:
            messages.error(request, "Please fill in all required fields.")
            return redirect("user_cart")

    return redirect("user_cart")

    
        
@login_required(login_url='/auth/login/')
def about_view(request):
    return render(request, "base/about.html")


def contact_view(request):
    if request.method == 'POST':
        name = request.POST.get('name')
        email = request.POST.get('email')
        message = request.POST.get('message')
        
        if name and email and message:
            try:
                send_mail(
                    f"Message from {email,name}",
                    message,
                    email,
                    ['iqcollectionsstore@gmail.com'], 
                    fail_silently=False,
                )
                messages.success(request, "Your message has been sent successfully.")
                return redirect('contact')  
            except Exception as e:
                # Display the exact error in the message for debugging
                error_message = f"There was an error sending your message: {str(e)}"
                messages.error(request, error_message)
                return redirect('contact')
        else:
            messages.error(request, "Please fill in all fields.")
            return redirect('contact')
    return render(request, 'base/contact.html')


def contact_success(request):
    return render(request, 'base/contact_success.html')




def track_order_view(request):
    if request.method == "POST":
        order_id = request.POST.get("order_id", "").strip()
        try:
            # Fetch the order by ID
            order = Order.objects.get(id=order_id)
            
            # Ensure the order belongs to the logged-in user
            if order.user != request.user:
                messages.error(request, "You are not authorized to view this order.")
                return redirect("track_order")

            return render(request, "base/track_order.html", {"order": order})
        except Order.DoesNotExist:
            messages.error(request, "Order not found. Please check the Order ID.")
            return redirect("track_order")

    return render(request, "base/track_order_form.html")
