# Lab description
This is one of the most basic access controls ever applied. The role is specified in the request performed by the user, which is an user-controllable field. A simple manipulation of this parameter can lead to a privilege escalation routine.

# Writeup
We access to the website and login as wiener:peter.
When accessing, I notice that in the URL my name exists:
![[user_role_controlled_by_request_parameter.png]]

I don't remember this functionality before, so I change it to administrator, but I get redirected to the login page. 
Analyzing the request, I see that a cookie with "Admin=false" name is being to the server. User controllable input. Let's change it to "true" and send the request:
![[user_role_controlled_by_request_parameter-1.png]]

Let's visit the admin panel: 
![[user_role_controlled_by_request_parameter-2.png]]

And delete the user carlos:
![[user_role_controlled_by_request_parameter-3.png]]



