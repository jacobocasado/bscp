
# Lab description
This lab uses the `X-Original-URL` and `X-Rewrite-URL` headers to rewrite the URL and bypass the access controls that use hardcoded URLs, like `DENY: POST, /admin/deleteUser, managers`.

We will craft a URL with these headers to bypass the URL restriction that is being performed by the server.

Info of the lab:
> However, the back-end application is built on a framework that supports the `X-Original-URL` header.

# Writeups
Let's visit the page and go to the /admin panel. We won't be able to access:
![[imgs/broken_access_control_url_rewrite.png]]

![[imgs/broken_access_control_url_rewrite-1.png]]

Let's inspect the original request:
![[imgs/broken_access_control_url_rewrite-2.png]]

Okay, the request is to /admin. The lab info said that the framework uses the `X-Original-URL` header, so let's do the following to try to bypass the /admin detection that seems to happen here:

- Craft a GET request to / (root). This request is not blocked by any rule.
- Add the `X-Original-URL` header with value `/admin`, that will override the / path in the request, and bypass the access control detection performed by the server.

Sending this crafted request leads to a 200 OK and an admin panel disclosure:
![[imgs/broken_access_control_url_rewrite-3.png]]

Now, let's use this technique and modify the `X-Original-URL` header to` /admin/delete?username=carlos`, to delete carlos. Note that **we have to specify the parameter "carlos" as the username in the original request, and it is not valid if we add the parameters in the HEADER**:
![[imgs/broken_access_control_url_rewrite-4.png]]

By doing that, the lab was solved:
![[imgs/broken_access_control_url_rewrite-5.png]]