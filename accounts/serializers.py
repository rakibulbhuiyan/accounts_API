from django.contrib.auth.models import User
from rest_framework import serializers
from rest_framework.authtoken.models import Token


class Userserializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    confirm_password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ['username', 'firstname', 'lastname', 'email', 'password', 'confirm_password']
        extra_kwargs = {
            'password': {'write_only': True},
            'confirm_password': {'write_only': True}
        }

        def validate(self, data):
            password = data['password']
            confirm_password = data['confirm_password']
            if password != confirm_password:
                raise serializers.ValidationError('password do not match')
            else:
                return data

        def create(self, validate_data):
            password = validate_data.pop('password')
            validate_data.pop('confirm_password')  # here we remove confirm password . we use it only for match.

            # now here we need to create a new user and set password for it
            user = User.objects.create(**validate_data)
            user.set_password(password)
            user.save()

            # Now we need to create a token for new user
            Token.objects.create(user=user)
            return user
