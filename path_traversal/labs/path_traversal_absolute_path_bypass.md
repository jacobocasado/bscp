We are going to bypass the defense mechanism of the server by adding an absolute route to the path.

The vulnerable point might be in the images:
![](imgs/path_traversal_absolute_path_bypass.png)

Scanning with Burp Suite, we get that indeed that point is vulnerable to path traversal:
![](imgs/path_traversal_absolute_path_bypass-1.png)

We can see that the exploit used is the absolute route, `/etc/passwd`, without a traversal payload:
![](imgs/path_traversal_absolute_path_bypass-2.png)


