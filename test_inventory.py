import inventory
import pytest


def test_normal_email():
    # Validates normal values passed return correct values
    assert inventory.get_user_email("firstname", "lastname", "usertype", "orgdomain") == \
           "firstname.lastname@usertype.orgdomain"


def test_blanks():
    # Validates that blank arguments return none
    assert inventory.get_user_email("", "", "", "") is None

