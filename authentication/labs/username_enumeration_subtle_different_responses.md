This lab is similar to [username_enumeration_subtle_different_responses](username_enumeration_subtle_different_responses.md) but is harder to see the difference of the response given between a valid and a wrong user.

This is that we get on a wrong user:
![](imgs/username_enumeration_subtle_different_responses.png)

But now the concept is "Invalid username or password".
We will make a grep operation for this exact string:
![](imgs/username_enumeration_subtle_different_responses-1.png)

And perform a bruteforce on the users based on this criteria to see which response is different:
![](imgs/username_enumeration_subtle_different_responses-2.png)

Filtering by the column tells us that the response is different, a dot trail is missing. That can be translated as the user is probably valid, or different from the rest, which are invalid.
![](imgs/username_enumeration_subtle_different_responses-3.png)

That means probably `apple:thomas` is the way to go here.
![](imgs/username_enumeration_subtle_different_responses-4.png)




