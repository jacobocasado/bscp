Stored DOM XSS.
Let's find the piece of code that is vulnerable and tells us that there is an stored DOM XSS:

![](imgs/dom_xss_stored.png)

Here we have the `innerHTML` sink that has `comment.author` within a `escapeHTML` function. 
This function does the following:
![](imgs/dom_xss_stored-1.png)

BUT, **this function does not replace all the occurrences as the `replace` function does not replace ALL THE OCURRENCES BUT THE FIRST ONES, so we can add an extra > and < into our payload at first, and then our payload.**
Let's create the payload (remember, the author is the vulnerable field):
![](imgs/dom_xss_stored-2.png)
But this payload does not work:
![](imgs/dom_xss_stored-4.png)

Trying with the recommended payload (`<><img src=1 onerror=alert(1)>`) using the same bypass technique gives us an XSS:
![](imgs/dom_xss_stored-3.png)

Remember to use `img` and `iframe` payloads instead of `script`.

