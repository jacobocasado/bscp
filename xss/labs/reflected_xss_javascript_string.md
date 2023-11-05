This is the vulnerable code:
![](imgs/reflected_xss_javascript_string.png)

We can try to break this variable and execute code inside the `script` tag that is already created. Example payloads are:
`-alert(document.domain)-`

We have to scape the variable, which is inside quotas, so we need to add a quota before , and another after that, to be correctly closed. The payload would be:
`'-alert(1)-'

![](imgs/reflected_xss_javascript_string-1.png)![](imgs/reflected_xss_javascript_string-2.png)

This is the code with the payload:
![](imgs/reflected_xss_javascript_string-3.png)

We are basically creating a variable with quotas and then substracting our script, so the script must be rendered for the variable to be created.


