# What is path traversal
Path traversal, also known as **directory traversal**, is a vulnerability that enables attackers to read **arbitrary files** on the server that is running the application.

These files can be important files for further attacks, like: 
- Application code and data (**aka. source code**)
- Credentials of users, back-end systems, etc.
- Sensitive OS files.

Besides being a read vulnerability, exploiting it can lead to further attacks.

**In some cases, an attacker might be able to WRITE arbitrary files on the server, allowing them to modify application data or behavior, and therefore, take control of the server.**

# Reading arbitrary files via path traversal
Imagine a shopping application that displays images of items for sale. This might load an image using the following HTML:
`<img src="/loadImage?filename=218.png">`

The `loadImage` URL takes a `filename` parameter and returns the contents of the specified file. The image files are stored on disk in the location `/var/www/images/`. To return an image, the application appends the requested filename to this base directory and uses a filesystem API to read the contents of the file. In other words, the application reads from the following file path:
`/var/www/images/218.png`

This application implements no defenses against path traversal attacks. As a result, an attacker can request the following URL to retrieve the `/etc/passwd` file from the server's filesystem:
`https://insecure-website.com/loadImage?filename=../../../etc/passwd`

This causes the application to read from the following file path:
`/var/www/images/../../../etc/passwd`

The sequence `../` is valid within a file path, and means to step up one level in the directory structure. The three consecutive `../` sequences step up from `/var/www/images/` to the filesystem root, and so the file that is actually read is:
`/etc/passwd`

On Unix-based operating systems, this is a standard file containing details of the users that are registered on the server, but an attacker could retrieve other arbitrary files using the same technique.

**On Windows, both `../` and `..\` are valid directory traversal sequences. The following is an example of an equivalent attack against a Windows-based server:**
`https://insecure-website.com/loadImage?filename=..\..\.`

Here is a lab that covers this topic: [simple_path_traversal](labs/simple_path_traversal.md)

# Common defenses to exploiting path traversal vulnerabilities
Many applications that place user input into file paths implement defenses against path traversal attacks. **But these defenses commonly can be bypassed.**

If an application **strips or blocks path traversal sequences from an user-supplied filename, these defenses can often be bypassed by using a variety of techniques.**

We can, for example, use **absolute paths instead of performing a relative path traversal attack.** For example, we might use as payload `filename=/etc/passwd`, to directly reference a file without using any traversal sequences.
Here is a lab that covers this attack: [path_traversal_absolute_path_bypass](labs/path_traversal_absolute_path_bypass.md)

We might be able to use nested traversal sequences, such as `....//` or `....\/`. These revert to simple traversal sequences when the inner sequence is stripped, bypassing another possible verification mechanism.
Here is a lab that covers this topic: [path_traversal_stripping_bypass](labs/path_traversal_stripping_bypass.md)

In some contexts, such as in a URL path or the `filename` parameter of a `multipart/form-data` request, web servers may strip any directory traversal sequences before passing your input to the application. You can sometimes bypass this kind of sanitization by URL encoding, or even double URL encoding, the `../` characters.
This results in `%2e%2e%2f` and `%252e%252e%252f` respectively. Various non-standard encodings, such as `..%c0%af` or `..%ef%bc%8f`, may also work.

This is the double encoding technique, which consists in encoding first the payload (`../`) and then the `%` resultant from encoding these payloads.
Step 1: `../` to `%2e%2e%2f`
Step 2: `%2e%2e%2f` to `%252e%252e%252f`
Here is a lab that covers this technique to perform an attack: [path_traversal_bypass_double_encoding](labs/path_traversal_bypass_double_encoding.md)

For [Burp Suite Professional](https://portswigger.net/burp/pro) users, Burp Intruder provides the predefined payload list **Fuzzing - path traversal**. This contains some encoded path traversal sequences that you can try.

An application may require the user-supplied filename to start with the expected base folder, such as `/var/www/images`. In this case, it might be possible to include the required base folder followed by suitable traversal sequences. For example:
`filename=/var/www/images/../../../etc/passwd`

An application may require the user-supplied filename to end with an expected file extension, such as `.png`. In this case, it might be possible to use a null byte to effectively terminate the file path before the required extension. For example:
`filename=../../../etc/passwd%00.png`

Here is a lab that covers this topic: [path_traversal_null_byte_bypass](labs/path_traversal_null_byte_bypass.md)

An application may require the user-supplied filename to start with the expected base folder, such as `/var/www/images`. In this case, it might be possible to include the required base folder followed by suitable traversal sequences. For example:
`filename=/var/www/images/../../../etc/passwd`