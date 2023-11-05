# How to prevent XSS

In this section, we'll describe some general principles for preventing [cross-site scripting](https://portswigger.net/web-security/cross-site-scripting) vulnerabilities and ways of using various common technologies for protecting against [XSS](https://portswigger.net/web-security/cross-site-scripting) attacks.

Cross-site scripting prevention can generally be achieved via two layers of defense:

- [Encode data on output](https://portswigger.net/web-security/cross-site-scripting/preventing#encode-data-on-output)
- [Validate input on arrival](https://portswigger.net/web-security/cross-site-scripting/preventing#validate-input-on-arrival)

You can use Burp Scanner to scan your web sites for numerous security vulnerabilities including XSS. Burp's cutting-edge scanning logic replicates the actions of a skilled attacker and is able to achieve correspondingly high coverage of XSS vulnerabilities. You can use Burp Scanner to gain assurance that your defenses against XSS attacks are working effectively.

[Learn more about Burp Scanner](https://portswigger.net/burp/vulnerability-scanner)

## Encode data on output

Encoding should be applied directly before user-controllable data is written to a page, because the context you're writing into determines what kind of encoding you need to use. For example, values inside a JavaScript string require a different type of escaping to those in an HTML context.

In an HTML context, you should convert non-whitelisted values into HTML entities:

- `<` converts to: `&lt;`
- `>` converts to: `&gt;`

In a JavaScript string context, non-alphanumeric values should be Unicode-escaped:

- `<` converts to: `\u003c`
- `>` converts to: `\u003e`

Sometimes you'll need to apply multiple layers of encoding, in the correct order. For example, to safely embed user input inside an event handler, you need to deal with both the JavaScript context and the HTML context. So you need to first Unicode-escape the input, and then HTML-encode it:

`<a href="#" onclick="x='This string needs two layers of escaping'">test</a>`

## Validate input on arrival

Encoding is probably the most important line of XSS defense, but it is not sufficient to prevent XSS vulnerabilities in every context. You should also validate input as strictly as possible at the point when it is first received from a user.

Examples of input validation include:

- If a user submits a URL that will be returned in responses, validating that it starts with a safe protocol such as HTTP and HTTPS. Otherwise someone might exploit your site with a harmful protocol like `javascript` or `data`.
- If a user supplies a value that it expected to be numeric, validating that the value actually contains an integer.
- Validating that input contains only an expected set of characters.

Input validation should ideally work by blocking invalid input. An alternative approach, of attempting to clean invalid input to make it valid, is more error prone and should be avoided wherever possible.

### Whitelisting vs blacklisting

Input validation should generally employ whitelists rather than blacklists. For example, instead of trying to make a list of all harmful protocols (`javascript`, `data`, etc.), simply make a list of safe protocols (HTTP, HTTPS) and disallow anything not on the list. This will ensure your defense doesn't break when new harmful protocols appear and make it less susceptible to attacks that seek to obfuscate invalid values to evade a blacklist.

## Allowing "safe" HTML

Allowing users to post HTML markup should be avoided wherever possible, but sometimes it's a business requirement. For example, a blog site might allow comments to be posted containing some limited HTML markup.

The classic approach is to try to filter out potentially harmful tags and JavaScript. You can try to implement this using a whitelist of safe tags and attributes, but thanks to discrepancies in browser parsing engines and quirks like mutation XSS, this approach is extremely difficult to implement securely.

The least bad option is to use a JavaScript library that performs filtering and encoding in the user's browser, such as DOMPurify. Other libraries allow users to provide content in markdown format and convert the markdown into HTML. Unfortunately, all these libraries have XSS vulnerabilities from time to time, so this is not a perfect solution. If you do use one you should monitor closely for security updates.

#### Note

In addition to JavaScript, other content such as CSS and even regular HTML can be harmful in some situations.

[Attacks using malicious CSS](https://portswigger.net/research/detecting-and-exploiting-path-relative-stylesheet-import-prssi-vulnerabilities#badcss)

## How to prevent XSS using a template engine

Many modern websites use server-side template engines such as Twig and Freemarker to embed dynamic content in HTML. These typically define their own escaping system. For example, in Twig, you can use the `e()` filter, with an argument defining the context:

`{{ user.firstname | e('html') }}`

Some other template engines, such as Jinja and React, escape dynamic content by default which effectively prevents most occurrences of XSS.

We recommend reviewing escaping features closely when you evaluate whether to use a given template engine or framework.

#### Note

If you directly concatenate user input into template strings, you will be vulnerable to [server-side template injection](https://portswigger.net/kb/issues/00101080_server-side-template-injection) which is often more serious than XSS.

## How to prevent XSS in PHP

In PHP there is a built-in function to encode entities called `htmlentities`. You should call this function to escape your input when inside an HTML context. The function should be called with three arguments:

- Your input string.
- `ENT_QUOTES`, which is a flag that specifies all quotes should be encoded.
- The character set, which in most cases should be UTF-8.

For example:

`<?php echo htmlentities($input, ENT_QUOTES, 'UTF-8');?>`

When in a JavaScript string context, you need to Unicode-escape input as already described. Unfortunately, PHP doesn't provide an API to Unicode-escape a string. Here is some code to do that in PHP:

`<?php``function jsEscape($str) { $output = ''; $str = str_split($str); for($i=0;$i<count($str);$i++) { $chrNum = ord($str[$i]); $chr = $str[$i]; if($chrNum === 226) { if(isset($str[$i+1]) && ord($str[$i+1]) === 128) { if(isset($str[$i+2]) && ord($str[$i+2]) === 168) { $output .= '\u2028'; $i += 2; continue; } if(isset($str[$i+2]) && ord($str[$i+2]) === 169) { $output .= '\u2029'; $i += 2; continue; } } } switch($chr) { case "'": case '"': case "\n"; case "\r"; case "&"; case "\\"; case "<": case ">": $output .= sprintf("\\u%04x", $chrNum); break; default: $output .= $str[$i]; break; } } return $output; } ?>`

Here is how to use the `jsEscape` function in PHP:

`<script>x = '<?php echo jsEscape($_GET['x'])?>';</script>`

Alternatively, you could use a template engine.

## How to prevent XSS client-side in JavaScript

To escape user input in an HTML context in JavaScript, you need your own HTML encoder because JavaScript doesn't provide an API to encode HTML. Here is some example JavaScript code that converts a string to HTML entities:

`function htmlEncode(str){ return String(str).replace(/[^\w. ]/gi, function(c){ return '&#'+c.charCodeAt(0)+';'; }); }`

You would then use this function as follows:

`<script>document.body.innerHTML = htmlEncode(untrustedValue)</script>`

If your input is inside a JavaScript string, you need an encoder that performs Unicode escaping. Here is a sample Unicode-encoder:

`function jsEscape(str){ return String(str).replace(/[^\w. ]/gi, function(c){ return '\\u'+('0000'+c.charCodeAt(0).toString(16)).slice(-4); }); }`

You would then use this function as follows:

`<script>document.write('<script>x="'+jsEscape(untrustedValue)+'";<\/script>')</script>`

## How to prevent XSS in jQuery

The most common form of XSS in jQuery is when you pass user input to a jQuery selector. Web developers would often use `location.hash` and pass it to the selector which would cause XSS as jQuery would render the HTML. jQuery recognized this issue and patched their selector logic to check if input begins with a hash. Now jQuery will only render HTML if the first character is a `<`. If you pass untrusted data to the jQuery selector, ensure you correctly escape the value using the `jsEscape` function above.

## Mitigating XSS using content security policy (CSP)

[Content security policy](https://portswigger.net/web-security/cross-site-scripting/content-security-policy) (CSP) is the last line of defense against cross-site scripting. If your XSS prevention fails, you can use CSP to mitigate XSS by restricting what an attacker can do.

CSP lets you control various things, such as whether external scripts can be loaded and whether inline scripts will be executed. To deploy CSP you need to include an HTTP response header called `Content-Security-Policy` with a value containing your policy.

An example CSP is as follows:

`default-src 'self'; script-src 'self'; object-src 'none'; frame-src 'none'; base-uri 'none';`

This policy specifies that resources such as images and scripts can only be loaded from the same origin as the main page. So even if an attacker can successfully inject an XSS payload they can only load resources from the current origin. This greatly reduces the chance that an attacker can exploit the XSS vulnerability.

If you require loading of external resources, ensure you only allow scripts that do not aid an attacker to exploit your site. For example, if you whitelist certain domains then an attacker can load any script from those domains. Where possible, try to host resources on your own domain.

If that is not possible then you can use hash- or nonce-based policy to allow scripts on different domains. A nonce is a random string that is added as an attribute of a script or resource, which will only be executed if the random string matches the server-generated one. An attacker is unable to guess the randomized string and therefore cannot invoke a script or resource with a valid nonce and so the resource will not be executed.

#### Read more

- [Mitigating XSS attacks using CSP](https://portswigger.net/web-security/cross-site-scripting/content-security-policy#mitigating-xss-attacks-using-csp)