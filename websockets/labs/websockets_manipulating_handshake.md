If we now try the XSS payload of before:
`<img src=1 onerror='alert()'>`

We can see that the attack has been detected:
![](imgs/websockets_manipulating_handshake.png)

And we can't perform more connections as our IP address has been banned.
We have to bypass the IP verification, that most of the time will be performed in the WebSocket handshake.

Going to the Burp Suite repeater and taking one of the previous WebSockets messages:
`X-Forwarded-For: 1.1.1.1`
![](imgs/websockets_manipulating_handshake-2.png)
![](imgs/websockets_manipulating_handshake-5.png)

Now we have bypassed the connection and we can try another payload.
We try an obfuscated payload:
``<img src=1 oNeRrOr=alert`1`>``
Which is just basically adding some uppercase characters. The property is still valid when uppercase, so the script works.
![](imgs/websockets_manipulating_handshake-3.png)

And the response is valid, which means that the script was injected:
![](imgs/websockets_manipulating_handshake-4.png)
