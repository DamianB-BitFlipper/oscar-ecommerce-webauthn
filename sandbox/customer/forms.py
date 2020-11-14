
from oscar.core.compat import get_user_model
from oscar.apps.customer.forms import EmailUserCreationForm as CoreEmailUserCreationForm

User = get_user_model()

class EmailUserCreationForm(CoreEmailUserCreationForm):
    class Meta:
        model = User
        fields = ('email',)
