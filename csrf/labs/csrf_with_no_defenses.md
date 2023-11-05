The first lab is to test how to use the CSRF PoC generator build into Burp Suite professional.

This is the request to change e-mail:
![](imgs/csrf_with_no_defenses.png)

We have to play around this in the PoC generator.
Rightclicking and clicking on "Engagement tools > Generate CSRF PoC:"
![](imgs/csrf_with_no_defenses-1.png)

We copy the generated HTML:
![](imgs/csrf_with_no_defenses-2.png)

And paste it into the exploit server:
![](imgs/csrf_with_no_defenses-3.png)

