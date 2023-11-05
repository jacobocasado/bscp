To PWN this AngularJS lab, they have an special payload for AngularJS:
`{{$on.constructor('alert(1)')()}}`

Whatever is inside `ng-app` is being evaluated. In this lab, the whole body of the app is inside `ng-app`:

![](imgs/dom_xss_angularjs_expresion.png)

We can control the parameter of the search, as I introduced an `s`. 
Let's try using the payload that they give us:
![](imgs/dom_xss_angularjs_expresion-1.png)

Another tip to know if the page uses AngularJS is to look in the Burp Suite scanner:
![](imgs/dom_xss_angularjs_expresion-2.png)

Or just look inside the source code: 
![](imgs/dom_xss_angularjs_expresion-3.png)
