We have the option to stay logged in:
![](imgs/bypass_stay_logged_in_cookie.png)

Let's see the cookie that the server gives us when we tick this option: 
![](imgs/bypass_stay_logged_in_cookie-1.png)

We can see that is base64 of the user and then a big string. We have to see what is that long string. Based on the size it can be a hash,so let's copy it into a hash recognizer page:
![](imgs/bypass_stay_logged_in_cookie-2.png)

It's probably MD5, let's hash the username or the password to see if it is any of those fields hashed:
![](imgs/bypass_stay_logged_in_cookie-3.png)

We can see that is the password hashed, so let's just create a intruder attack using the wordlist and hashing MD5 the password before sending it:
![](imgs/bypass_stay_logged_in_cookie-4.png)

Now we process the payload to add carlos:`<word>` and then MD5 that. `<word>` will be from the wordlist given by Burp Suite. Finally, base64 all the payload:
![](imgs/bypass_stay_logged_in_cookie-7.png)

Now we send the attack and check which gives us a 200 OK:
![](imgs/bypass_stay_logged_in_cookie-9.png)

This cookie is static and we can add it to be logged in as Carlos whenever we want.
![](imgs/bypass_stay_logged_in_cookie-10.png)

