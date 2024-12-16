from django.contrib.auth import views as auth_views
from django.urls import path

from . import generic_views as V



urlpatterns = [
    path("", V.landing_page_view, name="home"),
    path("products/<category>/", V.products_view, name="products"),
    path("product-detail/<pk>/", V.product_detail_view, name="product_detail"),
    path("add-to-cart/<pk>/<quantity>/", V.add_cart_view, name="add_to_cart"),
    path("user-cart/", V.cart_view, name="user_cart"),
    path('cart/remove/<uuid:item_id>/', V.remove_from_cart, name='remove_from_cart'),
    path("place-order/", V.order_view, name="place_order"),
    path(
        "products/<str:category>/<str:sub>/",
        V.filter_products_view,
        name="filter_products",
    ),
    path("auth/<str:type>/", V.auth_view, name="auth" ),
    path("login/", V.login_view, name="login" ),
    path("signup/", V.signup_view, name="signup" ),
    path("logout/", V.signout, name="logout" ),
    path("about/", V.about_view, name="about" ),
    path("contact/",V.contact_view, name="contact"),
    path('contact_success/', V.contact_success, name='contact_success'),
]

