
# Lab description
The users in this lab access its acount via the `id` parameter in the request: 
`https://insecure-website.com/myaccount?id=123`

The lab is simple, changing this ID to the ID of another user leads us to getting its information.

# Writeup
When logged in as wiener:peter and visiting our profile, it leads us to this HTTP request:
![](imgs/horizontal_privesc_user_id_in_request.png)

We can see the ID displayed in the parameter... let's change it to carlos.
![](imgs/horizontal_privesc_user_id_in_request-1.png)

There we have it, there is no validation, so just changing the ID leads us to horizontal privesc.


