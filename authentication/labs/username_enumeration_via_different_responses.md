If we try to log in with an user that does not exist, the response includes "Invalid username":
![](imgs/username_enumeration_via_different_responses.png)
![](imgs/username_enumeration_via_different_responses-1.png)

Let's use the wordlist to enumerate users:
![](imgs/username_enumeration_via_different_responses-2.png)

We can see that with the username `agenda`, we get a different response that does not include the "Invalid username".
The next step is to bruteforce the password:
![](imgs/username_enumeration_via_different_responses-3.png)

With `michael` we get redirected to `/my-account?id=agenda`, which means we probably logged in. Let's try:
![](imgs/username_enumeration_via_different_responses-4.png)
