
# Lab description
Continuation of [[user_role_controlled_by_request_parameter]], but in this case, the parameter is not going to be predictable, as before (there was an Admin cookie xD).
Let's go!

# Writeup
Visiting the page and login in as wiener:peter leads us to our account showing an API key and a ID in the request that differs from this API key:
![[user_role_controlled_by_request_parameter_unpredictable_parameter-1.png]]

If we go to the posts, we can see that there is one post made by the administrator user:
![[user_role_controlled_by_request_parameter_unpredictable_parameter-2.png]]

Visiting the source code **leaks its user ID**:
![[user_role_controlled_by_request_parameter_unpredictable_parameter-3.png]]

We can try to use this User ID to authenticate as him:
![[user_role_controlled_by_request_parameter_unpredictable_parameter-4.png]]

But the lab asks to find the GUID for the user carlos, so we need a post for carlos (or a comment, or anything that leaks its GUID). Here we have a post of carlos:
![[user_role_controlled_by_request_parameter_unpredictable_parameter-5.png]]

Obtaining its GUID as we did with admin and putting it into a request, leads us to the panel of carlos:
![[user_role_controlled_by_request_parameter_unpredictable_parameter-7.png]]

![[user_role_controlled_by_request_parameter_unpredictable_parameter-6.png]]

Submitting its API key leads us to the completion of the lab:
![[user_role_controlled_by_request_parameter_unpredictable_parameter-8.png]]