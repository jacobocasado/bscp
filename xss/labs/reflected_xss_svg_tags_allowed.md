This lab has a simple [reflected XSS](https://portswigger.net/web-security/cross-site-scripting/reflected) vulnerability. The site is blocking common tags but misses some SVG tags and events.
To solve the lab, perform a [cross-site scripting](https://portswigger.net/web-security/cross-site-scripting) attack that calls the `alert()` function.

For this, we will:
1. Find the vulnerable reflected XSS section
2. Fuzz with a lot of payloads

This is the vulnerable XSS section:
![](imgs/reflected_xss_svg_tags_allowed.png)

We now have to fuzz with a lot of payloads, taking the payloads with the [XSS cheat sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)
![](imgs/reflected_xss_svg_tags_allowed-1.png)

Putting our list of payloads:
![](imgs/reflected_xss_svg_tags_allowed-2.png)

This is very slow, so I first detect which HTML tag is the one allowed:
![](imgs/reflected_xss_svg_tags_allowed-3.png)

`animatetransform` is allowed:
![](imgs/reflected_xss_svg_tags_allowed-4.png)

We copy all the payloads that have this tag:
![](imgs/reflected_xss_svg_tags_allowed-5.png)

I tried with the first payload of this type:
![](imgs/reflected_xss_svg_tags_allowed-6.png)

And it worked, we got XSS:![](imgs/reflected_xss_svg_tags_allowed-7.png)

![](imgs/reflected_xss_svg_tags_allowed-8.png)