This lab contains a SQL injection vulnerability in the product category filter. The results from the query are returned in the application's response, so you can use a UNION attack to retrieve data from other tables. To construct such an attack, you need to combine some of the techniques you learned in previous labs.

The database contains a different table called `users`, with columns called `username` and `password`.

To solve the lab, perform a [SQL injection UNION](https://portswigger.net/web-security/sql-injection/union-attacks) attack that retrieves all usernames and passwords, and use the information to log in as the `administrator` user.

To solve the lab we just have to add an UNION payload to get username and password from the table USERS.

We just add the following SQLi:
`Gifts'+UNION+SELECT+username,+password+FROM+users--`
![](imgs/sqli_retrieving_data_from_other_tables.png)
