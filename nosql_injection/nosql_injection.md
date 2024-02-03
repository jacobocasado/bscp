NoSQL injection occurs when an attacker can modify the NosQL queries performed to the underlying database. 
NoSQL injection allows an attacker to:
- Bypass authentication mechanisms
- Extract or edit data
- Erase data
- Cause a denial of service
- Sometimes, execute code on the server

NoSQL databases are different and store and retrieve data in a different way then SQL relational tables. Also, the language used in NoSQL queries can differ as it is not a **universal language like SQL, and have fewer relational constraints.**

There are two different types of NoSQL injection, syntax injection and operator injection. Syntax injection occurs when you can break the noSQL syntax and introduce your own payload. The problem with NoSQL is that there is a lot of query languages, types of query syntax and data structures so sometimes inject query is much more difficult.

Operator injection is when you are capable of injecting an operator to manipulate the query.
MongoDB is the most common NoSQL database.

# Testing for NoSQL syntax injection
You can potentially detect NoSQL injection vulnerabilities by attempting to break the query syntax. To do this, systematically test each input by submitting fuzz strings and special characters that trigger a database error or some other detectable behavior if they're not adequately sanitized or filtered by the application.

If you know the API language of the target database, use special characters and fuzz strings that are relevant to that language. Otherwise, use a variety of fuzz strings to target multiple API languages.

### Detecting syntax injection in MongoDB
Consider a shopping application that displays products in different categories. When the user selects the **Fizzy drinks** category, their browser requests the following URL:

`https://insecure-website.com/product/lookup?category=fizzy`

This causes the application to send a JSON query to retrieve relevant products from the `product` collection in the MongoDB database:
`this.category == 'fizzy'`

To test whether the input may be vulnerable, submit a fuzz string in the value of the `category` parameter. An example string for MongoDB is:
``'"`{ ;$Foo} $Foo \xYZ``

Use this fuzz string to construct the following attack:

`https://insecure-website.com/product/lookup?category='%22%60%7b%0d%0a%3b%24Foo%7d%0d%0a%24Foo%20%5cxYZ%00`

If this causes a change from the original response, this may indicate that user input isn't filtered or sanitized correctly.
## Note
NoSQL injection vulnerabilities can occur in a variety of contexts, and you need to adapt your fuzz strings accordingly. Otherwise, you may simply trigger validation errors that mean the application never executes your query.

In this example, we're injecting the fuzz string via the URL, so the string is URL-encoded. In some applications, you may need to inject your payload via a JSON property instead. In this case, this payload would become ``'\"`{\r;$Foo}\n$Foo \\xYZ\u0000``.

## Determining which characters are processed
To determine which characters are interpreted as syntax by the application, you can inject individual characters. For example, you could submit `'`, which results in the following MongoDB query:
`this.category == '''`

If this causes a change from the original response, this may indicate that the `'` character has broken the query syntax and caused a syntax error. You can confirm this by submitting a valid query string in the input, for example by escaping the quote:

`this.category == '\''`

If this doesn't cause a syntax error, this may mean that the application is vulnerable to an injection attack.

## Confirming conditional behavior
After detecting a vulnerability, the next step is to determine whether you can influence boolean conditions using NoSQL syntax.

To test this, send two requests, one with a false condition and one with a true condition. For example you could use the conditional statements `' && 0 && 'x` and `' && 1 && 'x` as follows:

`https://insecure-website.com/product/lookup?category=fizzy'+%26%26+0+%26%26+'x``https://insecure-website.com/product/lookup?category=fizzy'+%26%26+1+%26%26+'x`

If the application behaves differently, this suggests that the false condition impacts the query logic, but the true condition doesn't. This indicates that injecting this style of syntax impacts a server-side query.

## Overriding existing conditions
Now that you have identified that you can influence boolean conditions, you can attempt to override existing conditions to exploit the vulnerability. For example, you can inject a JavaScript condition that always evaluates to true, such as `'||1||'`:
`https://insecure-website.com/product/lookup?category=fizzy%27%7c%7c%31%7c%7c%27`

This results in the following MongoDB query:

`this.category == 'fizzy'||'1'=='1'`

As the injected condition is always true, the modified query returns all items. This enables you to view all the products in any category, including hidden or unknown categories.
You could also add a null character after the category value. MongoDB may ignore all characters after a null character. This means that any additional conditions on the MongoDB query are ignored. For example, the query may have an additional `this.released` restriction:

`this.category == 'fizzy' && this.released == 1`

The restriction `this.released == 1` is used to only show products that are released. For unreleased products, presumably `this.released == 0`.

In this case, an attacker could construct an attack as follows:

`https://insecure-website.com/product/lookup?category=fizzy'%00`

This results in the following NoSQL query:

`this.category == 'fizzy'\u0000' && this.released == 1`

If MongoDB ignores all characters after the null character, this removes the requirement for the released field to be set to 1. As a result, all products in the `fizzy` category are displayed, including unreleased products.

Here is a lab in which we detect the NoSQL injection and modify the original query with a query injection: [nosql_injection](nosql_injection.md)
### Warning
Take care when injecting a condition that always evaluates to true into a NoSQL query. Although this may be harmless in the initial context you're injecting into, it's common for applications to use data from a single request in multiple different queries. If an application uses it when updating or deleting data, for example, this can result in accidental data loss.


# NoSQL operator injection
NoSQL databases often use query operators, which provide ways to specify conditions that data must meet to be included in the query result. Examples of MongoDB query operators include:

- `$where` - Matches documents that satisfy a JavaScript expression.
- `$ne` - Matches all values that are not equal to a specified value.
- `$in` - Matches all of the values specified in an array.
- `$regex` - Selects documents where values match a specified regular expression.

You may be able to inject query operators to manipulate NoSQL queries. To do this, systematically submit different operators into a range of user inputs, then review the responses for error messages or other changes.

## Submitting query operators
In JSON messages, you can insert query operators as nested objects. For example, `{"username":"wiener"}` becomes `{"username":{"$ne":"invalid"}}`.

For URL-based inputs, you can insert query operators via URL parameters. For example, `username=wiener` becomes `username[$ne]=invalid`. If this doesn't work, you can try the following:

1. Convert the request method from `GET` to `POST`.
2. Change the `Content-Type` header to `application/json`.
3. Add JSON to the message body.
4. Inject query operators in the JSON.

### Detecting operator injection in MongoDB
Consider a vulnerable application that accepts a username and password in the body of a `POST` request:
`{"username":"wiener","password":"peter"}`

Test each input with a range of operators. For example, to test whether the username input processes the query operator, you could try the following injection:
`{"username":{"$ne":"invalid"},"password":{"peter"}}`

If the `$ne` operator is applied, this queries all users where the username is not equal to `invalid`.

If both the username and password inputs process the operator, it may be possible to bypass authentication using the following payload:
`{"username":{"$ne":"invalid"},"password":{"$ne":"invalid"}}`

This query returns all login credentials where both the username and password are not equal to `invalid`. As a result, you're logged into the application as the first user in the collection.

To target an account, you can construct a payload that includes a known username, or a username that you've guessed. For example:
`{"username":{"$in":["admin","administrator","superadmin"]},"password":{"$ne":""}}`

This will select the first ocurrence of those users in the query and return its password.
The following lab was based in performing this attack to guess the username of admin and entering without knowing its password, bypassing authentication: [nosql_operator_injection](labs/nosql_operator_injection.md)

# Exploiting syntax injection to extract data
In many NoSQL databases, some query operators or functions can run limited JavaScript code, such as MongoDB's `$where` operator and `mapReduce()` function. This means that, if a vulnerable application uses these operators or functions, the database may evaluate the JavaScript as part of the query. You may therefore be able to use JavaScript functions to extract data from the database.

## Exfiltrating data in MongoDB
Consider a vulnerable application that allows users to look up other registered usernames and displays their role. This triggers a request to the URL:
`https://insecure-wbsite.com/user/lookup?username=admin`

This results in the following NoSQL query of the `users` collection:
`{"$where":"this.username == 'admin'"}`

As the query uses the `$where` operator, you can attempt to inject JavaScript functions into this query so that it returns sensitive data. For example, you could send the following payload:
`admin' && this.password[0] == 'a' || 'a'=='b`

This returns the first character of the user's password string, enabling you to extract the password character by character.

You could also use the JavaScript `match()` function to extract information. For example, the following payload enables you to identify whether the password contains digits:
`admin' && this.password.match(/\d/) || 'a'=='b`

Here is a lab that covers the discovery of the credentials of the administrator user with these techniques: [nosql_injection_extract_data](labs/nosql_injection_extract_data.md)

# Exploiting NoSQL operator injection to extract data
Even if the original query doesn't use any operators that enable you to run arbitrary JavaScript, you may be able to inject one of these operators yourself. You can then use boolean conditions to determine whether the application executes any JavaScript that you inject via this operator.
## Injecting operators in MongoDB
Consider a vulnerable application that accepts username and password in the body of a `POST` request:
`{"username":"wiener","password":"peter"}`

To test whether you can inject operators, you could try adding the `$where` operator as an additional parameter, then send one request where the condition evaluates to false, and another that evaluates to true. For example:
`{"username":"wiener","password":"peter", "$where":"0"}`
`{"username":"wiener","password":"peter", "$where":"1"}`

If there is a difference between the responses, this may indicate that the JavaScript expression in the `$where` clause is being evaluated.
#### Extracting field names
If you have injected an operator that enables you to run JavaScript, you may be able to use the `keys()` method to extract the name of data fields. For example, you could submit the following payload:
`"$where":"Object.keys(this)[0].match('^.{0}a.*')"`

This inspects the first data field in the user object and returns the first character of the field name. This enables you to extract the field name character by character, and then construct the attack as usual, once fields are known.

Here is the lab that covers the discovery of these fields: