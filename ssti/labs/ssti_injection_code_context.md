We have the "post comment" functionality:
![](imgs/Untitled.png)

We are going to try a basic Tornado template:
![](imgs/Untitled-1.png)

The template does not get displayed, but we have our user name displayed in the comment:
![](imgs/Untitled-2.png)

We can also modify our user name, so it may have the template injection there.
We can choose to display the user name:
![](imgs/Untitled-3.png)

And we can try to inject SSTI code here. This will append the SSTI in the code:
![](imgs/Untitled-4.png)

We are basically injecting code and we are closing the template and starting a new one.
By creating a new comment we can see we have injected code:![](imgs/Untitled-5.png)

We can try to execute code here with the following structure:
```
{% import os %}{{ os.popen("whoami").read() }}
```
![](imgs/Untitled-6.png)

We can see that the `whoami` command displays the user `carlos`:
![](imgs/Untitled-7.png)

We are just going to delete the file:
`user.name}}{%25+import+os+%25}{{os.system('rm%20/home/carlos/morale.txt')`
![](imgs/Untitled-9.png)

When reading the comment, the command gets executed and we delete the file:
![](imgs/Untitled-10.png)