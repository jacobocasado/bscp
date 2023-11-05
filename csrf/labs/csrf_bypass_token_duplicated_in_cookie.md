First, we can see that the CSRF token value matches in both fields:
![](imgs/csrf_bypass_token_duplicated_in_cookie.png)

Once we find the vulnerability that allows us to inject a cookie into the user's session, we just add the same cookie as the CSRF part of the form:
![](imgs/csrf_bypass_token_duplicated_in_cookie-1.png)

The request will set a csrf cookie called "fake" and then send a POST form with the CSRF token with the same value.
![](imgs/csrf_bypass_token_duplicated_in_cookie-2.png)

