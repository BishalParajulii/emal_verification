from django.shortcuts import redirect, render
from django.http import HttpResponse
from django.contrib.auth.models import User
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.sites.shortcuts import get_current_site
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes,force_str
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import send_mail

# Create your views here.
def home(request):
    return render(request, "authentication/index.html")

def signup(request):

    if request.method == 'POST':
       print(request.POST)
       username = request.POST.get('username')
       firstname = request.POST.get('fname')
       lastname = request.POST.get('lname')
       email = request.POST.get('email')
       pass1 = request.POST.get('pass1')
       pass2 = request.POST.get('pass2')

       if pass1 != pass2:
            messages.error(request, "Passwords do not match.")
            return render(request, "authentication/signup.html")
       
       if User.objects.filter(username=username).exists():
            messages.error(request, "Username already exists. Please choose a different username.")
            return render(request, "authentication/signup.html")
       if len(username)>20:
            messages.error(request, "Username must be under 20 charcters!!")
            return render(request,"authentication/signup.html")
       if not username.isalnum():
            messages.error(request, "Username must be Alpha-Numeric!!")
            return render(request,"authentication/signup.html")

       myuser = User.objects.create_user(username, email, pass1)
       myuser.first_name = firstname
       myuser.last_name = lastname

       myuser.is_active = False

       myuser.save()


        # Email Address Confirmation
       current_site = get_current_site(request)
       email_subject = "Confirm your email @ GFG - Django login"
       message2 = render_to_string('email_confirmation.html', {
            'name': myuser.first_name,
            'domain': current_site.domain,
            'uid': urlsafe_base64_encode(force_bytes(myuser.pk)),
            'token': default_token_generator.make_token(myuser),
        })

        # Send email
       send_mail(
            email_subject,
            message2,
            'noreply@pythondjango.com',  # Use a generic email address or one provided by your service
            [email],
            fail_silently=False,
        )


       messages.success(request, "Your Account has been successfully created. Check your email to activate your account.")
       return render(request, "authentication/signup.html")  


    return render(request, "authentication/signup.html")

def signin(request):

    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']

        user = authenticate(request, username=username, password=password)

        if user is not None:
            login(request, user)
            firstname = user.first_name
            return render(request, "authentication/index.html", {'firstname': firstname})

        else:
            messages.error(request, "Bad Credentials!")
            return render(request, "authentication/signin.html")

    return render(request, "authentication/signin.html")

def signout(request):
    logout(request)
    messages.success(request, "Logged Out Successfully")
    return redirect('home')


def activate(request , uidb64 , token):
    try:
        uid =force_str(urlsafe_base64_decode(uidb64))
        myuser = User.objects.get(pk=uid)

    except(TypeError , ValueError , OverflowError , User.DoesNotExist):
        myuser = None


    if myuser is not None and default_token_generator.check_token(myuser , token):
        myuser.is_active = True
        myuser.save()
        login(request , myuser)
        return redirect('home')

    else:
        return render(request, 'activation_failed.html')