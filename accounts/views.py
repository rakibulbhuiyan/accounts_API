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
                return Response({'msg': 'User not found'}, status=status.HTTP_400_BAD_REQUEST)
        user = User.objects.all()
        serializer = Userserializer(user, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    @csrf_exempt
    def post(self, request):
        data = request.data
        serializer = Userserializer(data=data)
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            user = User.request.get(username=data['username'])
            token = Token.objects.get(user=user)
            return Response(
                {
                    'message': 'user create successfully',
                    'user': request.data,
                    'token': token.key
                }, status=status.HTTP_200_OK
            )
        else:
            res_error = serializer.errors
            return Response(res_error, status=status.HTTP_400_BAD_REQUEST)

    @csrf_exempt
    def put(self, request, id=None):
        if id:
            data = request.data
            user = User.request.get(id=id)
            serializer = Userserializer(user, data=data)
            if serializer.is_valid(raise_exception=True):
                serializer.save()
                msg = {'msg': 'Data complete update successfully'}
                return Response(msg, status=status.HTTP_200_OK)
            else:
                msg = serializer.errors
                return Response(msg, status=status.HTTP_501_NOT_IMPLEMENTED)

        else:
            msg = {'error': 'Id not found'}
            return Response(msg, status=status.HTTP_501_NOT_IMPLEMENTED)

    @csrf_exempt
    def prefetch(self, request, id=None):
        if id:
            data = request.data
            user = User.request.get(id=id)
            serializer = Userserializer(user, data=data, partial=True)
            if serializer.is_valid(raise_exception=True):
                serializer.save()
                msg = {'msg': 'Data partial update successfully'}
                return Response(msg, status=status.HTTP_200_OK)
            else:
                msg = serializer.errors
                return Response(msg, status=status.HTTP_501_NOT_IMPLEMENTED)

        else:
            msg = {'error': 'Id not found'}
            return Response(msg, status=status.HTTP_501_NOT_IMPLEMENTED)

    @csrf_exempt
    def delete(self, request, id=None):
        if id:
            user = User.request.get(id=id)
            if user:
                user.delete()
                msg = {'msg': 'Data Deleted successfully'}
                return Response(msg, status=status.HTTP_200_OK)
            else:
                msg = {'error': 'User is not found'}
                return Response(msg, status=status.HTTP_404_NOT_FOUND)
        else:
            msg = {'error': 'Id not found'}
            return Response(msg, status=status.HTTP_501_NOT_IMPLEMENTED)


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
