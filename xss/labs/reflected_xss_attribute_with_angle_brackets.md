This lab shows us that there can be more than one site where our payload is being rendered.

When we insert a XSS payload, it gets shown in two places:
![](imgs/reflected_xss_attribute_with_angle_brackets.png)

![](imgs/reflected_xss_attribute_with_angle_brackets-1.png)

Indeed, we can close the attribute by adding `"` and adding whatever else:
![](imgs/reflected_xss_attribute_with_angle_brackets-2.png)

There is an attribute called `onmouseover` that executes whatever we add if we hover the mouse inside it. Adding the payload `"onmousemove="alert(1)"` , the first quotes to close the attribute and then adding our malicious attribute, makes our text execute XSS if we hover over it:
![](imgs/reflected_xss_attribute_with_angle_brackets-4.png)

