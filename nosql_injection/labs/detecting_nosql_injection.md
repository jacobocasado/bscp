
Here is the page that probably contains a NoSQL query:
![](imgs/detecting_nosql_injection.png)

Introducing a single quote breaks the query, which leads to this error which tells us that it is a MongoDB database:![](imgs/detecting_nosql_injection-1.png)

Now, we have to display the unreleased products. Let's try to not display any product with an AND opeator with null and X:
`Gifts' && 0 && 'x`
![](imgs/detecting_nosql_injection-2.png)

Now, we can display ALL of the products with an expression that always evaluates to TRUE.
This can be a valid expression, appending an OR to the following conditions so the part of the query that says "UNRELEASED=FALSE" is optional:
`Gifts'||1||'`
![](imgs/detecting_nosql_injection-3.png)

We solved the lab.
![](imgs/detecting_nosql_injection-4.png)