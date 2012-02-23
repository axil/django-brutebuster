from django.contrib.auth.backends import ModelBackend
from django import forms
from django.conf import settings

from .middleware import get_request
from .models import FailedAttempt

class ProtectedModelBackend(ModelBackend):
    def authenticate(self, username=None, password=None):
        
        request = get_request()
        if request:
            # try to get the remote address from thread locals
            IP_ADDR = request.META.get('REMOTE_ADDR', None)
        else:
            IP_ADDR = None
        
        try:
            fa = FailedAttempt.objects.filter(username=username, IP=IP_ADDR)[0]
            if fa.recent_failure():
                if fa.too_many_failures():
                    # we block the authentication attempt because
                    # of too many recent failures
                    fa.failures += 1
                    fa.save()
                    if getattr(settings, 'BB_EXPLICIT_MESSAGE', False):
                        raise forms.ValidationError('Too many failed attempts, try again later')
                    else:
                        return None
            else:
                # the block interval is over, so let's start
                # with a clean sheet
                fa.failures = 0
                fa.save()
        except IndexError:
            # No previous failed attempts
            fa = None

        result = super(ProtectedModelBackend, self).authenticate(username, password)
        if result:
            # the authentication was successful - we do nothing
            # special
            return result
        # the authentication was kaput, we should record this
        fa = fa or FailedAttempt (username=username, IP=IP_ADDR, failures=0)
        fa.failures+=1
        fa.save()
        # return with unsuccessful auth
        return None
