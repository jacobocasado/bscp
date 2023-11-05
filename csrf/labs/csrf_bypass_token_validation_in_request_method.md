The token validation is performed in the POST method, but not in the GET method.
Let's see the POST request; we can see that there is a CSRF token:
![](imgs/csrf_bypass_token_validation_in_request_method.png)

To change the method to GET, just right click on the request and click on "Change request method":
![](imgs/csrf_bypass_token_validation_in_request_method-2.png)

The method has been changed to GET:
![](imgs/csrf_bypass_token_validation_in_request_method-3.png)
Now, let's generate the CSRF PoC and paste it into the exploit server:
![](imgs/csrf_bypass_token_validation_in_request_method-4.png)

