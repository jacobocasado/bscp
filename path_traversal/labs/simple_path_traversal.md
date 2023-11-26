We have to get the contents of `/etc/passwd` file.

Here we can see the possible entry point of a path traversal:
![](imgs/simple_path_traversal.png)

Scanning this insertion point we can see the path traversal vulnerability:
![](imgs/simple_path_traversal-1.png)

And indeed we can see that we have the path traversal vulnerability exploited:
![](imgs/simple_path_traversal-2.png)

