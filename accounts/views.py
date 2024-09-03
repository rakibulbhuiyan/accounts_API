from django.shortcuts import render
from rest_framework import serializers, status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.authtoken.models import Token
from rest_framework.permissions import IsAuthenticated
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout
from django.views.decorators.csrf import csrf_exempt, csrf_protect
from .serializers import Userserializer


# Create your views here.

class RegistrationAPI(APIView):
    def get(self, request, id=None):
        if id:
            try:
                user = User.objects.get(id=id)
                serializer = Userserializer(user)
                return Response(serializer.data, status=status.HTTP_200_OK)
            except User.DoesNotExist:
                return Response({'msg': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
        
        users = User.objects.all()
        serializer = Userserializer(users, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    @csrf_exempt
    def post(self, request):
        data = request.data
        serializer = Userserializer(data=data)
        if serializer.is_valid(raise_exception=True):
            user = serializer.save()
            token = Token.objects.get(user=user)  # Create token after saving the user
            return Response(
                {
                    'message': 'User created successfully',
                    'user': serializer.data,
                    'token': token.key
                }, status=status.HTTP_201_CREATED
            )
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @csrf_exempt
    def put(self, request, id=None):
        if id:
            try:
                user = User.objects.get(id=id)
            except User.DoesNotExist:
                return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
            
            serializer = Userserializer(user, data=request.data)
            if serializer.is_valid(raise_exception=True):
                serializer.save()
                return Response({'msg': 'Data completely updated successfully'}, status=status.HTTP_200_OK)
            else:
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        else:
            return Response({'error': 'ID not provided'}, status=status.HTTP_400_BAD_REQUEST)

    @csrf_exempt
    def patch(self, request, id=None):
        if id:
            try:
                user = User.objects.get(id=id)
            except User.DoesNotExist:
                return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

            serializer = Userserializer(user, data=request.data, partial=True)
            if serializer.is_valid(raise_exception=True):
                serializer.save()
                return Response({'msg': 'Data partially updated successfully'}, status=status.HTTP_200_OK)
            else:
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        else:
            return Response({'error': 'ID not provided'}, status=status.HTTP_400_BAD_REQUEST)

    @csrf_exempt
    def delete(self, request, id=None):
        if id:
            try:
                user = User.objects.get(id=id)
            except User.DoesNotExist:
                return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

            user.delete()
            return Response({'msg': 'User deleted successfully'}, status=status.HTTP_200_OK)
        else:
            return Response({'error': 'ID not provided'}, status=status.HTTP_400_BAD_REQUEST)


class LoginView(APIView):
    @csrf_exempt
    def post(self, request):
        data = request.data
        username = data.get('username')
        password = data.get('password')
        if not username:
            return Response({'error': 'Username should not be empty'}, status=status.HTTP_400_BAD_REQUEST)
        if not password:
            return Response({'error': 'password should not be empty'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            as_user = User.objects.get(username=username)
        except User.DoesNotExist:
            return Response({'error': 'Username not found'}, status=status.HTTP_404_NOT_FOUND)
        if not as_user.check_password(password):
            return Response({'error': 'Password not match'}, status=status.HTTP_400_BAD_REQUEST)

        auth_user = authenticate(username=username, password=password)

        if auth_user is not None:
            user = User.objects.get(username=username)
            serializer = Userserializer(user)
            msg = {
                'message': 'User login successfull',
                'data': serializer.data,
            }
            token, create = Token.objects.get_or_create(user=user)
            msg['token'] = token.key
            return Response(msg, status=status.HTTP_200_OK)
        else:
            msg = {'error': 'Auth user is none'}
            return Response(msg, status=status.HTTP_401_UNAUTHORIZED)


class LogoutView(APIView):
    
    permission_class = [IsAuthenticated]

    @csrf_exempt
    def post(self, request):
        user = request.user
        token = Token.objects.get(user=user)
        if token:
            token.delete()
            msg = {'message': 'User logout successfully'}
            return Response(msg, status=status.HTTP_200_OK)
        else:
            msg = {'error': 'token not found'}
            return Response(msg, status=status.HTTP_404_NOT_FOUND)
