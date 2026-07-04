"""Regression wrapper: the mandated script name (inject_attacks.py) isn't
collected by pytest's test_* convention, so re-export its test here."""
from tests.adversarial.inject_attacks import test_all_attacks_rejected

__all__ = ["test_all_attacks_rejected"]
