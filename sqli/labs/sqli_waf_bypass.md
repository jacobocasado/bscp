We have the SQL injection in an XML entity. 
Adding an SQL payload in the StoreId throws an attack detection:
![](imgs/sqli_waf_bypass.png)

We are going to encode the payload using the Hackvertor extension. 
Encoding it with `hex_entities`:
![](imgs/sqli_waf_bypass-1.png)

We can see that we have bypassed the SQL injection:
![](imgs/sqli_waf_bypass-2.png)

Using the UNION SELECT NULL technique, we can obtain the number of columns:
![](imgs/sqli_waf_bypass-3.png)

We can see that it is 1 column, as if we insert 2 NULLs, a 0 is returned:
![](imgs/sqli_waf_bypass-4.png)

Taking this into account: we have to extract the password of the administrator user:
![](imgs/sqli_waf_bypass-5.png)

![](imgs/sqli_waf_bypass-6.png)