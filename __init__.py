"""
Module preventing Brute Force attacks against
django.contrib.auth.authenticate()
"""

from django.contrib import auth
from BruteBuster.decorators import protect_and_serve

# here we override the default authenticate method with the decorated version
auth.authenticate  = protect_and_serve (auth.authenticate)
