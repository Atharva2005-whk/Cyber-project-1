import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from detectors.dns_tunnel import shannon_entropy, DnsTunnelDetector


class FakeNotifier:
    pass


def test_entropy_of_empty_string_is_zero():
    assert shannon_entropy("") == 0.0


def test_entropy_of_repeated_char_is_zero():
    assert shannon_entropy("aaaaaaaa") == 0.0


def test_entropy_of_random_looking_string_is_higher_than_word():
    normal = shannon_entropy("google")
    random_ish = shannon_entropy("kx9fz2plq8wj")
    assert random_ish > normal


def test_should_flag_long_query():
    detector = DnsTunnelDetector(FakeNotifier(), max_query_length=20, entropy_threshold=99)
    assert detector.should_flag("a" * 25) is True


def test_should_flag_high_entropy_query():
    detector = DnsTunnelDetector(FakeNotifier(), max_query_length=999, entropy_threshold=3.0)
    assert detector.should_flag("kx9fz2plq8wjabcd") is True


def test_should_not_flag_normal_query():
    detector = DnsTunnelDetector(FakeNotifier(), max_query_length=60, entropy_threshold=3.5)
    assert detector.should_flag("www") is False
