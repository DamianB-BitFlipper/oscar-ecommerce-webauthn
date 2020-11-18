from django import http
from django.conf import settings
from django.contrib import messages
from django.contrib.auth import login as auth_login
from django.shortcuts import redirect
from django.urls import reverse
from django.utils.translation import gettext_lazy as _
from django.views import generic

from oscar.core.compat import get_user_model
from oscar.core.loading import get_class, get_classes
from oscar.apps.customer import signals

import os
import sys

from customer.utils import RP_ID, RP_NAME, ORIGIN
import customer.utils as utils
import webauthn

PageTitleMixin = get_class('customer.mixins', 'PageTitleMixin')
ConfirmPasswordForm = get_class('customer.forms', 'ConfirmPasswordForm')

RegisterUserMixin = get_class('customer.mixins', 'RegisterUserMixin')
EmailAuthenticationForm, EmailUserCreationForm = get_classes(
    'customer.forms', ['EmailAuthenticationForm', 'EmailUserCreationForm'])

User = get_user_model()

# Trust anchors (trusted attestation roots) should be
# placed in TRUST_ANCHOR_DIR.
TRUST_ANCHOR_DIR = 'trusted_attestation_roots'

class AccountAuthView(RegisterUserMixin, generic.TemplateView):
    """
    This is actually a slightly odd double form view that allows a customer to
    either login or register.
    """
    template_name = 'sandbox/customer/login_registration.html'
    login_prefix, registration_prefix = 'login', 'registration'
    login_form_class = EmailAuthenticationForm
    registration_form_class = EmailUserCreationForm
    redirect_field_name = 'next'

    def get(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            return redirect(settings.LOGIN_REDIRECT_URL)
        return super().get(
            request, *args, **kwargs)

    def get_context_data(self, *args, **kwargs):
        ctx = super().get_context_data(*args, **kwargs)
        if 'login_form' not in kwargs:
            ctx['login_form'] = self.get_login_form()
        if 'registration_form' not in kwargs:
            ctx['registration_form'] = self.get_registration_form()
        return ctx

    def post(self, request, *args, **kwargs):
        # TODO: It would be nice to have the different request.path
        # be handled by different views/separate `post` functions
        # like through an APIView
        if 'register_begin' in request.path:
            return self.webauthn_begin_register(request)
        elif 'register_finish' in request.path:
            return self.webauthn_finish_register(request)
        elif 'login_begin' in request.path:
            return self.webauthn_begin_login(request)
        elif 'login_finish' in request.path:
            return self.webauthn_finish_login(request)
        
        return http.HttpResponseBadRequest()

    # LOGIN

    def get_login_form(self, bind_data=False):
        return self.login_form_class(
            **self.get_login_form_kwargs(bind_data))

    def get_login_form_kwargs(self, bind_data=False):
        kwargs = {}
        kwargs['request'] = self.request
        kwargs['host'] = self.request.get_host()
        kwargs['prefix'] = self.login_prefix
        kwargs['initial'] = {
            'redirect_url': self.request.GET.get(self.redirect_field_name, ''),
        }

        if bind_data and self.request.method in ('POST', 'PUT'):
            kwargs.update({
                'data': self.request.POST,
                'files': self.request.FILES,
            })

        return kwargs

    def validate_login_form(self):
        form = self.get_login_form(bind_data=True)
        if form.is_valid():
            user = form.get_user()

            # Grab a reference to the session ID before logging in
            old_session_key = self.request.session.session_key

            auth_login(self.request, form.get_user())

            # Raise signal robustly (we don't want exceptions to crash the
            # request handling). We use a custom signal as we want to track the
            # session key before calling login (which cycles the session ID).
            signals.user_logged_in.send_robust(
                sender=self, request=self.request, user=user,
                old_session_key=old_session_key)

            msg = self.get_login_success_message(form)
            if msg:
                messages.success(self.request, msg)

            return redirect(self.get_login_success_url(form))

        ctx = self.get_context_data(login_form=form)
        return self.render_to_response(ctx)

    def webauthn_begin_login(self, request):
        session = request.session

        email = request.POST.get('login-username')

        if not utils.validate_username(email):
            return http.JsonResponse({'fail': 'Invalid username.'}, status=401)

        user = User.objects.get(email=email)

        if not user:
            return http.JsonResponse({'fail': 'User does not exist.'}, status=401)
        if not user.credential_id:
            return http.JsonResponse({'fail': 'Unknown credential ID.'}, status=401)

        session.pop('challenge', None)

        challenge = utils.generate_challenge(32)

        # We strip the padding from the challenge stored in the session
        # for the reasons outlined in the comment in webauthn_begin_activate.
        session['challenge'] = challenge.rstrip('=')

        display_name = user.email
        webauthn_user = webauthn.WebAuthnUser(
            user.ukey, user.username, display_name, user.icon_url,
            user.credential_id, user.pub_key, user.sign_count, user.rp_id)

        webauthn_assertion_options = webauthn.WebAuthnAssertionOptions(
            webauthn_user, challenge)

        return http.JsonResponse(webauthn_assertion_options.assertion_dict)

    def webauthn_finish_login(self, request):
        session = request.session
    
        challenge = session.get('challenge')
    
        assertion_response = request.POST
        credential_id = assertion_response.get('id')

        user = User.objects.get(credential_id=credential_id)

        if not user:
            return http.JsonResponse({'fail': 'User does not exist.'}, status=401)

        display_name = user.email
        webauthn_user = webauthn.WebAuthnUser(
            user.ukey, user.username, display_name, user.icon_url,
            user.credential_id, user.pub_key, user.sign_count, user.rp_id)

        webauthn_assertion_response = webauthn.WebAuthnAssertionResponse(
            webauthn_user,
            assertion_response,
            challenge,
            ORIGIN,
            uv_required=False)  # User Verification
   
        try:
            sign_count = webauthn_assertion_response.verify()
        except Exception as e:
            return http.JsonResponse({'fail': 'Assertion failed. Error: {}'.format(e)}, status=401)

        form = self.get_login_form(bind_data=True)

        # Attempt the log in
        if form.is_valid():
            # TODO: This may have race conditions if log in at same 
            # time from different places 
            #
            # Increment the user signature count
            user.sign_count = sign_count
            user.save()

            logged_in_user = form.get_user()

            # Grab a reference to the session ID before logging in
            old_session_key = self.request.session.session_key

            auth_login(self.request, form.get_user())

            # Raise signal robustly (we don't want exceptions to crash the
            # request handling). We use a custom signal as we want to track the
            # session key before calling login (which cycles the session ID).
            signals.user_logged_in.send_robust(
                sender=self, request=request, user=logged_in_user,
                old_session_key=old_session_key)

            msg = self.get_login_success_message(form)
            if msg:
                messages.success(request, msg)

            return http.JsonResponse({'nexturl': self.get_login_success_url(form)})

        return http.JsonResponse({'fail': 'Failed to log in user.\n' + form.errors.as_text()}, 
                                 status=401)

    def get_login_success_message(self, form):
        return _("Welcome back")

    def get_login_success_url(self, form):
        redirect_url = form.cleaned_data['redirect_url']
        if redirect_url:
            return redirect_url

        # Redirect staff members to dashboard as that's the most likely place
        # they'll want to visit if they're logging in.
        if self.request.user.is_staff:
            return reverse('dashboard:index')

        return settings.LOGIN_REDIRECT_URL

    # REGISTRATION

    def get_registration_form(self, bind_data=False, instance=None):
        return self.registration_form_class(
            **self.get_registration_form_kwargs(bind_data, instance))

    def get_registration_form_kwargs(self, bind_data=False, instance=None):
        kwargs = {}
        kwargs['host'] = self.request.get_host()
        kwargs['prefix'] = self.registration_prefix
        kwargs['initial'] = {
            'redirect_url': self.request.GET.get(self.redirect_field_name, ''),
        }

        if bind_data and self.request.method in ('POST', 'PUT'):
            kwargs.update({
                'data': self.request.POST,
                'files': self.request.FILES,
            })

        if instance is not None:
            kwargs['instance'] = instance

        return kwargs

    def validate_registration_form(self):
        form = self.get_registration_form(bind_data=True)
        if form.is_valid():
            self.register_user(form)

            msg = self.get_registration_success_message(form)
            messages.success(self.request, msg)

            return redirect(self.get_registration_success_url(form))

        ctx = self.get_context_data(registration_form=form)
        return self.render_to_response(ctx)

    def webauthn_begin_register(self, request):
        session = request.session
    
        # MakeCredentialOptions
        email = request.POST.get('registration-email')
    
        #clear session variables prior to starting a new registration
        session.pop('register_ukey', None)
        session.pop('register_username', None)
        session.pop('challenge', None)

        session['register_username'] = email

        challenge = utils.generate_challenge(32)
        ukey = utils.generate_ukey()

        # We strip the saved challenge of padding, so that we can do a byte
        # comparison on the URL-safe-without-padding challenge we get back
        # from the browser.
        # We will still pass the padded version down to the browser so that the JS
        # can decode the challenge into binary without too much trouble.
        session['challenge'] = challenge.rstrip('=')
        session['register_ukey'] = ukey
    
        display_name = email
        make_credential_options = webauthn.WebAuthnMakeCredentialOptions(
            challenge, RP_NAME, RP_ID, ukey, email, display_name,
            ORIGIN, attestation='none')

        return http.JsonResponse(make_credential_options.registration_dict)

    def webauthn_finish_register(self, request):
        session = request.session
    
        challenge = session['challenge']
        ukey = session['register_ukey']

        registration_response = request.POST
        trust_anchor_dir = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), TRUST_ANCHOR_DIR)
        trusted_attestation_cert_required = False
        self_attestation_permitted = True
        none_attestation_permitted = True

        webauthn_registration_response = webauthn.WebAuthnRegistrationResponse(
            RP_ID,
            ORIGIN,
            registration_response,
            challenge,
            trust_anchor_dir,
            trusted_attestation_cert_required,
            self_attestation_permitted,
            none_attestation_permitted,
            uv_required=False)  # User Verification

        try:
            webauthn_credential = webauthn_registration_response.verify()
        except Exception as e:
            return http.JsonResponse({'fail': 'Registration failed. Error: {}'.format(e)}, 
                                     status=401)

        # Step 17.
        #
        # Check that the credentialId is not yet registered to any other user.
        # If registration is requested for a credential that is already registered
        # to a different user, the Relying Party SHOULD fail this registration
        # ceremony, or it MAY decide to accept the registration, e.g. while deleting
        # the older registration.
        if User.objects.filter(credential_id=webauthn_credential.credential_id).exists():
            return http.JsonResponse({'fail': 'Credential ID already exists.'},  status=401)

        if sys.version_info >= (3, 0):
            webauthn_credential.credential_id = str(
                webauthn_credential.credential_id, "utf-8")
            webauthn_credential.public_key = str(
                webauthn_credential.public_key, "utf-8")

        # Create a `new_user` and assign to it the webauthn-specific fields
        new_user = User()
        new_user.ukey = ukey
        new_user.pub_key = webauthn_credential.public_key
        new_user.credential_id = webauthn_credential.credential_id
        new_user.sign_count = webauthn_credential.sign_count
        new_user.rp_id = RP_ID
        new_user.icon_url = 'https://127.0.0.1:8000'

        form = self.get_registration_form(bind_data=True, instance=new_user)

        if form.is_valid():
            self.register_user(form)

            msg = self.get_registration_success_message(form)
            messages.success(request, msg)

            return http.JsonResponse({'nexturl': self.get_registration_success_url(form)})

        return http.JsonResponse({'fail': 'Failed to register user.\n' + form.errors.as_text()},
                                 status=401)

    def get_registration_success_message(self, form):
        return _("Thanks for registering!")

    def get_registration_success_url(self, form):
        redirect_url = form.cleaned_data['redirect_url']
        if redirect_url:
            return redirect_url

        return settings.LOGIN_REDIRECT_URL

class ProfileDeleteView(PageTitleMixin, generic.FormView):
    form_class = ConfirmPasswordForm
    template_name = 'sandbox/customer/profile/profile_delete.html'
    page_title = _('Delete profile')
    active_tab = 'profile'
    success_url = settings.OSCAR_HOMEPAGE

    def post(self, request, *args, **kwargs):
        # TODO: It would be nice to have the different request.path
        # be handled by different views/separate `post` functions
        # like through an APIView
        if 'delete_begin' in request.path:
            return self.webauthn_begin_delete_profile(request)
        elif 'delete_finish' in request.path:
            return self.webauthn_finish_delete_profile(request)

        return http.HttpResponseBadRequest()

    def webauthn_begin_delete_profile(self, request):
        session = request.session

        user = request.user

        if not user:
            return http.JsonResponse({'fail': 'User does not exist.'}, status=401)
        if not user.credential_id:
            return http.JsonResponse({'fail': 'Unknown credential ID.'}, status=401)

        session.pop('challenge', None)
        session.pop('clientExtensions', None)

        challenge = utils.generate_challenge(32)

        # We strip the padding from the challenge stored in the session
        # for the reasons outlined in the comment in webauthn_begin_activate.
        session['challenge'] = challenge.rstrip('=')
        session['clientExtensions'] = {'txAuthSimple': "Confirm deletion of account {}!".
                                       format(user.email)}

        display_name = user.email
        webauthn_user = webauthn.WebAuthnUser(
            user.ukey, user.username, display_name, user.icon_url,
            user.credential_id, user.pub_key, user.sign_count, user.rp_id)

        webauthn_assertion_options = webauthn.WebAuthnAssertionOptions(
            webauthn_user, challenge,
            clientExtensions=session['clientExtensions'])

        return http.JsonResponse(webauthn_assertion_options.assertion_dict)

    def webauthn_finish_delete_profile(self, request):
        session = request.session
    
        challenge = session.get('challenge')
        clientExtensions = session.get('clientExtensions')
    
        assertion_response = request.POST
        credential_id = assertion_response.get('id')

        user = User.objects.get(credential_id=credential_id)

        if not user:
            return http.JsonResponse({'fail': 'User does not exist.'}, status=401)

        display_name = user.email
        webauthn_user = webauthn.WebAuthnUser(
            user.ukey, user.username, display_name, user.icon_url,
            user.credential_id, user.pub_key, user.sign_count, user.rp_id)

        # TODO: Shouldn't this extension verifier function be within the webauthn library?
        def verify_authenticator_extensions_fn(client_data, expected_authenticator_extensions):
            client_data_extensions = client_data.get('clientExtensions')
        
            # Make sure that the extensions dicts have the same keys
            if client_data_extensions.keys() != expected_authenticator_extensions.keys():
                return False

            # Make sure that the key is only `txAuthSimple` for now
            if client_data_extensions.keys() != {'txAuthSimple'}:
                return False

            # Test the `txAuthSimple` extension, except for line breaks
            if client_data_extensions['txAuthSimple'].replace('\n', '') != \
               expected_authenticator_extensions['txAuthSimple'].replace('\n', ''):
                return False

            # All passed
            return True

        webauthn_assertion_response = webauthn.WebAuthnAssertionResponse(
            webauthn_user,
            assertion_response,
            challenge,
            ORIGIN,
            uv_required=False, # User Verification
            expected_assertion_authenticator_extensions=clientExtensions,
            verify_authenticator_extensions_fn=verify_authenticator_extensions_fn,
        )
   
        try:
            sign_count = webauthn_assertion_response.verify()
        except Exception as e:
            return http.JsonResponse({'fail': 'Assertion failed. Error: {}'.format(e)}, status=401)

        form = self.get_form()

        # Attempt the profile deletion
        if form.is_valid():
            # TODO: This may have race conditions if log in at same 
            # time from different places 
            #
            # Increment the user signature count
            user.sign_count = sign_count
            user.save()

            next_url = self.form_valid(form)
            return http.JsonResponse({'nexturl': next_url})

        return http.JsonResponse({'fail': 'Failed to delete user.\n' + form.errors.as_text()}, 
                                 status=401)

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs['user'] = self.request.user
        return kwargs

    def form_valid(self, form):
        self.request.user.delete()
        messages.success(
            self.request,
            _("Your profile has now been deleted. Thanks for using the site."))
        return self.get_success_url()
