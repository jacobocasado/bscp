We can enumerate passwords of an user because of the following functionality:
![](imgs/brute_force_password_change.png)

If we insert a valid password but a different password for the confirmation1 and confirmation2, we get this message. We can try to enumerate valid passwords looking for this message, as the user is included as a parameter in the request:
![](imgs/brute_force_password_change-3.png)

This is when the password introduced is incorrect:
![](imgs/brute_force_password_change-1.png)

This is when the password introduced is correct: 
![](imgs/brute_force_password_change-2.png)


We can use this password to log in:
![](imgs/brute_force_password_change-4.png)

