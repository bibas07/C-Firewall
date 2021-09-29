from django.contrib.auth.models import User
from django.test import TestCase
from .models import Blacklist
from .models import Whitelist

# Create your tests here.
class WhitelistTest(TestCase):
    def add_whitelist(self, ip_address="192.168.23.5"):
        return Whitelist.objects.create(ip_address= ip_address)

    def test_add_whitelist(self):
        w = self.add_whitelist()
        self.assertTrue(isinstance(w, Whitelist))
        self.assertEqual(w.__str__(), w.ip_address)

class BlacklistTest(TestCase):
    def add_blacklist(self, ip_address="192.168.23.5"):
        return Blacklist.objects.create(ip_address= ip_address)

    def test_add_blacklist(self):
        w = self.add_blacklist()
        self.assertTrue(isinstance(w, Blacklist))
        self.assertEqual(w.__str__(), w.ip_address)
    
