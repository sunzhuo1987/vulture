# -*- coding: utf-8 -*-
from django.contrib.auth.models import User
import hashlib

class sql:
        def authenticate(self, username=None, password=None):
            try:
                user = User.objects.get(username__exact=username)
                if user.password == hashlib.sha1(password).hexdigest():
                    return user
            except User.DoesNotExist:
                return None
                
        def get_user(self, user_id):
            try:
                return User.objects.get(pk=user_id)
            except User.DoesNotExist:
                return None