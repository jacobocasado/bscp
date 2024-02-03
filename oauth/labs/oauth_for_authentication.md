We will exploit the OAuth flow used for authenticating an user, as this framework is not designed for authentication.

First, we log in with our credentials and inspect the requests that are being performed:

![](imgs/oauth_for_authentication.png)

This redirects us to another page, where we can log in. After logging in with our credentials, our page asks for resources:
![](imgs/oauth_for_authentication-1.png)

There is one of the requests that contain information about the user:
![](imgs/oauth_for_authentication-2.png)

We can see our user token. We can try to use **our token to ask for resources for other user, e.g., from carlos. We know his email, so we are going to ask for his data:**
![](imgs/oauth_for_authentication-4.png)

![](imgs/oauth_for_authentication-3.png)
