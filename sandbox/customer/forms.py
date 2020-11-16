from django import forms
from django.utils.translation import gettext_lazy as _

from oscar.core.compat import get_user_model
from oscar.apps.customer.forms import EmailUserCreationForm as CoreEmailUserCreationForm

import customer.utils as utils

User = get_user_model()

class EmailUserCreationForm(CoreEmailUserCreationForm):
    class Meta:
        model = User
        fields = ('email',)

    def clean_email(self):
        """
        Checks for existing users with the supplied email address.
        """
        email = super().clean_email()

        if not utils.validate_username(email):
            raise forms.ValidationError(_("Invalid email input."))

        return email
