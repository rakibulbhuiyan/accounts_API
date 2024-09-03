from django.contrib.auth.models import User
from rest_framework import serializers
from rest_framework.authtoken.models import Token


class Userserializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    confirm_password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ['username', 'first_name', 'last_name', 'email', 'password', 'confirm_password']
        extra_kwargs = {
            'password': {'write_only': True},
            'confirm_password': {'write_only': True}
        }

    def validate(self, data):
        # Checking for entered fields
        missing_fields = [field for field in self.fields if field not in data or data[field] == ""]
        if missing_fields:
            raise serializers.ValidationError({field: f"{field} is required." for field in missing_fields})

        # Checking password and confirm password match
        password = data.get('password')
        confirm_password = data.get('confirm_password')
        if password != confirm_password:
            raise serializers.ValidationError({'password': 'Passwords do not match'})

        return data

    def create(self, validated_data):
        # Remove confirm_password as it is not a field in the User model
        password = validated_data.pop('password')
        validated_data.pop('confirm_password')  # Remove confirm_password from validated_data

        # Creating a new user with the remaining data
        user = User.objects.create(**validated_data)
        user.set_password(password)  # Set the user's password correctly
        user.save()

        # Creating a token for the new user
        Token.objects.create(user=user)
        return user
