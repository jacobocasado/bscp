# What is Cross-Site Scripting (XSS)
XSS is a vulnerability that allows an attacker to compromise the interactions that users have with an application. This means that the normal interaction with the web application gets "poisoned" as it is possible to execute JavaScript code in the user's browser. 

If an attacker can control a script that is executed in the victim's browser, then they can typically fully compromise that user. Amongst other things, the attacker can:

- Perform any action within the application that the user can perform.
- View any information that the user is able to view.
- Modify any information that the user is able to modify.
- Initiate interactions with other application users, including malicious attacks, that will appear to originate from the initial victim user.

XSS **circunvents the Same Origin Policy**. The Same Origin Policy or SOP, is a security mechanisms that restricts how a script or document loaded by one origin **can interact with a resource from other origin.**
Taking as source the [Mozilla Web Docs](https://developer.mozilla.org/en-US/docs/Web/Security/Same-origin_policy) , two URLs have the same origin if the **protocol, port and host are the same for both.** This avoid an attacker from www[.]attacker[.] using scripts that access www[.]facebook[.]com, as the request made to this last one site does not match with protocol, port and host. 
By executing XSS, the attacker can load arbitrary JavaScript code inside the vulnerable application and carry any actions that the user is able to perform, or gain control over the user's cookies.

![](imgs/cross-site-scripting.svg)

Remember that we always use an alert script, but we can load scripts from our hosted application and load them in the vulnerable application, changing the behavior. But it's very common to use the `alert` payload because it's short, harmless and hard to miss as it is a simple word.

**Note that I read [this](https://portswigger.net/research/alert-is-dead-long-live-print) article** and now I don't use `alert` as the main PoC for my tests, as some browsers like Google Chrome have disabled `alert` from cross-origin iframes. Now I use `print()`, as this just offers to print a simple page and it avoids confusion with browsers. If `print` works, your XSS works.

# The three types of XSS attacks
The three main types of XSS attacks are:
- **Reflected XSS**, where the script comes embedded in the HTTP request that the user performs.
- **Stored XSS**, where the script comes from the website's database and is loaded by the user when accessing the database by any means.
- **DOM-based XSS**, where the vulnerability exists in client-side code instead of server-side code.
## Reflected XSS
Reflected XSS is the simplest version of XSS and the application receives the XSS payload in the HTTP request.
A common example is inside an URL: 
`https://insecure-website.com/status?message=All+is+well. <p>Status: All is well.</p>`

Imagine that the application does not process the data, so an attacker could craft an attack like the following, embedding an script:
`https://insecure-website.com/status?message=<script>/*+Bad+stuff+here...+*/</script> <p>Status: <script>/* Bad stuff here... */</script></p>`

If the user visits the URL, the malicious script will trigger, in the **context of that user's session within the application. The script can carry out any action and retrieve any data to which the user has access.** 
Nevertheless, this attack is less severe than stored XSS as the attacks need to be embedded in the request that the user performs. In the stored XSS, the payload can be inside the webpage, and the user loads it when rendering the webpage, without the need of adding it in the URL.

This opens the first reflected XSS lab: [reflected_xss_without_encoding](labs/reflected_xss_without_encoding.md).

## Stored XSS
Stored XSS arises when an application receives data, saves it in the application and then renders that data in an unsafe way. Imagine a website with blog posts, that allows users adding comments.
An attacker could add a JavaScript payload as a comment and the JavaScript code will get rendered in all of the user's browsers that see the comment.

We have an example on the first Stored XSS lab: 