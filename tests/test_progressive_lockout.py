"""
Tests for progressive lockout functionality.
"""
import pytest
from django.test import RequestFactory, TestCase
from django.contrib.auth import get_user_model
from nai_security.handlers.progressive_lockout import ProgressiveLockoutHandler

User = get_user_model()


class ProgressiveLockoutTests(TestCase):
    """Test progressive lockout handler."""
    
    def setUp(self):
        self.factory = RequestFactory()
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
    
    def test_lockout_duration_calculation(self):
        """Test lockout duration increases with attempts."""
        assert ProgressiveLockoutHandler.get_lockout_duration(1) == 0
        assert ProgressiveLockoutHandler.get_lockout_duration(3) == 0
        assert ProgressiveLockoutHandler.get_lockout_duration(4) == 5
        assert ProgressiveLockoutHandler.get_lockout_duration(6) == 5
        assert ProgressiveLockoutHandler.get_lockout_duration(7) == 10
        assert ProgressiveLockoutHandler.get_lockout_duration(10) == 15
        assert ProgressiveLockoutHandler.get_lockout_duration(13) == 60
    
    def test_increment_failure_count(self):
        """Test failure count increments correctly."""
        request = self.factory.post('/admin/login/', {
            'username': 'testuser',
            'password': 'wrong'
        })
        
        count1 = ProgressiveLockoutHandler.increment_failure_count(request)
        assert count1 == 1
        
        count2 = ProgressiveLockoutHandler.increment_failure_count(request)
        assert count2 == 2
    
    def test_lockout_after_threshold(self):
        """Test user gets locked out after threshold."""
        request = self.factory.post('/admin/login/', {
            'username': 'testuser',
            'password': 'wrong'
        })
        
        # Simulate 4 failed attempts
        for _ in range(4):
            ProgressiveLockoutHandler.increment_failure_count(request)
        
        # Should be locked out for 5 minutes
        assert ProgressiveLockoutHandler.is_locked_out(request)
        time_remaining = ProgressiveLockoutHandler.get_lockout_time_remaining(request)
        assert time_remaining is not None
        assert time_remaining <= 300  # 5 minutes in seconds
    
    def test_reset_on_success(self):
        """Test attempts reset on successful login."""
        request = self.factory.post('/admin/login/', {
            'username': 'testuser',
            'password': 'wrong'
        })
        
        # Fail a few times
        for _ in range(3):
            ProgressiveLockoutHandler.increment_failure_count(request)
        
        # Reset on success
        ProgressiveLockoutHandler.reset_attempts(request)
        
        # Count should be 0
        assert ProgressiveLockoutHandler.get_failure_count(request) == 0
        assert not ProgressiveLockoutHandler.is_locked_out(request)