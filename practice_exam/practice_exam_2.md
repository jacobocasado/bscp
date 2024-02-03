Again, probably reflected XSS on search bar:
![](imgs/practice_exam_2.png)

Exploiting it manually leads to the following WAF block:
![](imgs/practice_exam_2-1.png)

let's use eval + atob(base64): eval(atob(dW5kZWZpbmVk))
![](imgs/practice_exam_2-2.png)

We need a way to bypass this. Let's fuzz with intruder the possible tags:

