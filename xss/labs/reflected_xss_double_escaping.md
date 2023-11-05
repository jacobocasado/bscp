This lab contains a [reflected cross-site scripting](https://portswigger.net/web-security/cross-site-scripting/reflected) vulnerability in the search query tracking functionality where angle brackets and double are HTML encoded and single quotes are escaped.

To solve this lab, perform a cross-site scripting attack that breaks out of the JavaScript string and calls the `alert` function.

Let's see the vulnerable part of the page:
![](imgs/reflected_xss_double.png)

We can see that our code is being displayed on the page. Viewing the source code:
![](imgs/reflected_xss_double-1.png)

We can try to add the following payload, from other laboratory, to execute a javascript inside the same variable:
![](imgs/reflected_xss_double-2.png)

We can see that a backslash is being added to every quote to scape this quote and not treat it as a special character. **We have to intentionally add a backslash next to each quote so our backslash treats the backslash that is being added as a non-special character, bypassing this defense mechanism.**
![](imgs/reflected_xss_double-4.png)

Touching a bit the payload leads us to commenting the last part and adding a ; intentionally:
![](imgs/reflected_xss_double-5.png)

This is the final payload: `/?search=\'-alert(1);//'`

![](imgs/reflected_xss_double-6.png)