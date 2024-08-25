from django.urls import path
from .views import RegistrationAPI, LoginView, LogoutView
urlpatterns = [
    path('', RegistrationAPI.as_view(), name='user_list'),
    path('register/', RegistrationAPI.as_view(), name='register'),
    path('<int:id>/', RegistrationAPI.as_view(), name='register_user_details'),
    path('login/', LoginView.as_view(), name='login'),
    path('logout/', LogoutView.as_view(), name='logout'),
]