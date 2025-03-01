from django.urls import path
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from accounts.views import RegisterAPIView, ConfirmationCodeAPIView, PasswordResetRequestView, PasswordResetView, \
    UserInfo, LogoutAPIView

urlpatterns = [
    path('token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('Register/', RegisterAPIView.as_view(), name='register'),
    path('ConfirmationCodeAPIView/', ConfirmationCodeAPIView.as_view(), name='confirmation_code'),
    path('PasswordResetRequestView/', PasswordResetRequestView.as_view(), name='password_reset_request'),
    path('reset-password/<uid>/<token>/', PasswordResetView.as_view(), name='password_reset'),
    path('UserInfo/', UserInfo.as_view() , name='user_info'),
    path('LogoutAPIView/', LogoutAPIView.as_view(), name='logout_view'),

]