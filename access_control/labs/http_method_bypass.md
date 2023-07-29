# Lab description
This lab implements [access controls](https://portswigger.net/web-security/access-control) based partly on the HTTP method of requests. You can familiarize yourself with the admin panel by logging in using the credentials `administrator:admin`.

To solve the lab, log in using the credentials `wiener:peter` and exploit the flawed access controls to promote yourself to become an administrator.

# Writeup

Let's log in as administrator and check the HTTP methods that we have to access this panel. 
We have a section in which we can upgrade or downgrade a user:
![[http_method_bypass.png]]

This is the underlying request when upgrading carlos:
![[http_method_bypass-1.png]]

Performing this action as the normal user is not possible.
The next step I did was checking the HTTP OPTIONS of this request, to see if I could do a GET instead of a POST. But for some reasons, I could not get the OPTIONS method. 
I just simply changed the POST request to a GET request, and it worked. I could perform the same action with a POST than with a GET, but **obviously, i had to attach the parameters to the request instead to the BODY (as we are crafting a GET request)**:

![[http_method_bypass-2.png]]
It seems that it might be validating the existence of the POST message, but the functionality is also working on the GET message... We can bypass the restriction just by changing the HTTP method.

The next step is to log in as the wiener user and try to perform this bypass using GET instead of POST. For that, we just take the request to upgrade roles and change the cookie for the cookie of "wiener":
![[http_method_bypass-3.png]]

This way, upgrading the roles of wiener leads us to the lab completed:
![[http_method_bypass-4.png]]




