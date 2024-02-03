This lab is so simple. Just click on "Forgot password":
![](imgs/password_reset_broken_logic-1.png)
We introduce our username to get an email from which we can reset the password. In the page, we can see that the request to change password includes the user that we want to change the password:
![](imgs/password_reset_broken_logic-2.png)

We can change the username to `carlos` and just change the password. If the system does not validate that the user matches the user in the token, we can change the password of `carlos`.
![](imgs/password_reset_broken_logic-3.png)

Just log in with the new password:
![](imgs/password_reset_broken_logic.png)