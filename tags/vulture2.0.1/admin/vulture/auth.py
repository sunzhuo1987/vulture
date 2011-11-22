# -*- coding: utf-8 -*-
from django.contrib.auth.models import User
from django.db import connection
import hashlib

class sql:
	def authenticate(self, username=None, password=None):
		cursor = connection.cursor()
		cursor.execute("SELECT 1 FROM user WHERE username = %s AND password = %s", [username, hashlib.sha1(password).hexdigest()])
		row = cursor.fetchone()
		if not row:
			return None
		try:
			user = User.objects.get(username__exact=username)
		except:
			user = User.objects.create_user(username, '', '')
			user.save()			
		return user
		
	def get_user(self, user_id):
		try:
			return User.objects.get(pk=user_id)
		except User.DoesNotExist:
			return None
