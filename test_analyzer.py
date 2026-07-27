"""
Unit Tests for Password Guardian Pro
ST4017CMD Introduction to Programming - Coursework Project
"""

import unittest
from analyzer import PasswordAnalyzer, PasswordHistory

class TestPasswordAnalyzer(unittest.TestCase):
    """Test cases for password strength analysis"""
    
    def test_weak_password(self):
        """Test that 'abc123' is correctly identified as weak"""
        score, feedback, entropy, patterns = PasswordAnalyzer.analyze_strength("abc123")
        self.assertLess(score, 3, "Password 'abc123' should be weak (score < 3)")
    
    def test_strong_password(self):
        """Test that 'P@ssw0rd!2026' is correctly identified as strong"""
        score, feedback, entropy, patterns = PasswordAnalyzer.analyze_strength("P@ssw0rd!2026")
        self.assertGreaterEqual(score, 5, "Password 'P@ssw0rd!2026' should be strong (score >= 5)")
    
    def test_pattern_detection(self):
        """Test that common patterns are detected"""
        score, feedback, entropy, patterns = PasswordAnalyzer.analyze_strength("aaditya123")
        self.assertGreater(len(patterns), 0, "Should detect at least one pattern")
    
    def test_history_linked_list(self):
        """Test that the custom linked list works correctly"""
        history = PasswordHistory()
        history.add_entry("hash1", 5, 60.5)
        history.add_entry("hash2", 3, 45.2)
        entries = history.get_history()
        self.assertEqual(len(entries), 2, "History should have 2 entries")

if __name__ == "__main__":
    unittest.main()
  
