# What is information disclosure?
Information disclosure, also known as **information leakage,** is when a website **unintentionally** displays sensitive information to its users.

The displayed information can vary, and the application can leak all kinds of information. The common ones (that are interesting for an attacker) are:
- Data about other users, such as usernames or financial information
- Sensitive commercial or business data
- Technical details about the website and its infrastructure

The dangers of leaking this data are obvious, but disclosing technical information, such as versions or the framework that the website is using, can be just as serious. Although some of this information will be of limited use, it can potentially be a starting point for exposing an additional attack surface, which may contain other interesting vulnerabilities. 

Occasionally, sensitive information might be carelessly leaked to users who are simply browsing the website in a normal fashion. More commonly, however, an attacker needs to elicit the information disclosure by interacting with the website in unexpected or malicious ways. They will then carefully study the website's responses to try and identify interesting behavior.

# How do information disclosure vulnerabilities arise?
Information disclosure vulnerabilities can arise in countless different ways, but these can broadly be categorized as follows:

- **Failure to remove internal content from public content**. For example, developer comments in markup are sometimes visible to users in the production environment.
- **Insecure configuration of the website and related technologies**. For example, failing to disable debugging and diagnostic features can sometimes provide attackers with useful tools to help them obtain sensitive information. Default configurations can also leave websites vulnerable, for example, by displaying overly verbose error messages or having a debug mode that is visible or easily accessible (e.g., with no authentication).
- **Flawed design and behavior of the application**. For example, if a website returns distinct responses when different error states occur, this can also allow attackers to [enumerate sensitive data](https://portswigger.net/web-security/authentication/password-based#username-enumeration), such as valid user credentials.

# How to test for information disclosure vulnerabilities
Generally speaking, it is important not to develop "tunnel vision" during testing. In other words, you should avoid focusing too narrowly on a particular vulnerability. 
Sensitive data can be leaked in all kinds of places, so it is important not to miss anything that could be useful later. You will often find sensitive data while testing for something else. A key skill is being able to recognize interesting information whenever and wherever you do come across it.

The following are some examples of high-level techniques and tools that you can use to help identify information disclosure vulnerabilities during testing.

## Fuzzing 
If we identify interesting parameters, we can try to **submit unexpected data types and specially crafted fuzz strings to see what effect it has in the application.**
Also take into account that maybe the response can be the same, but the application's behavior is different. For example, the application takes more time to process the request. Even if the content of an error message doesn't disclose anything, sometimes the fact that one error case was encountered instead of another one is useful information in itself.

# Common sources of information disclosure
Information disclosure can occur in a wide variety of contexts within a website. The following are some common examples of places where you can look to see if sensitive information is exposed.

## Files for web crawlers
Many websites provide files at `/robots.txt` and `/sitemap.xml` to help crawlers navigate their site. Among other things, these files often list specific directories that the crawlers should skip, for example, because they may contain sensitive information.

As these files are not usually linked from within the website, **they may not immediately appear in Burp's site map.** However, it is worth trying to navigate to `/robots.txt` or `/sitemap.xml` manually to see if you find anything of use.

## Directory listings
Web servers can be configured to automatically list the contents of directories that do not have an index page present. This can help an attacker by enabling them to identify the resources at a given path and proceed directly to analyzing and attacking those resources.

## Developer comments
Sometimes, developers add comment to the HTML markup and these comments are typically forgotten, missed or left deliberately. Although these comments are not visible on the rendered page, we can see them reading the code of the webpage or in Burp Suite.

Occasionally, these comments contain information that is useful to an attacker. For example, they might hint at the existence of hidden directories or provide clues about the application logic.

## Error messages
One of the most common causes of information disclosure is **error messages.** As a general rule, we should pay more attention to all error messages encountered during auditing.

The content of this error messages can reveal information about **what input or data type is expected for a given parameter.** This can help us **narrow the attack** by identifying exploitable parameters. Or just avoid us wasting time injecting payloads that won't work.

This error messages can also leak information about the **technologies used by the website.** For example, the template engine, database type or server that the website is using. We can look for exploits or common configuration errors, or default settings that are dangerous.

This is a lab that covers the attack of adding an input that differs from the input that the website expects: [information_disclosure_error_messages](labs/information_disclosure_error_messages.md)

## Debugging data
For debugging purposes, many websites generate custom error messages and logs that contain a lot of information about the application's behavior. While this information is useful during development, it can be also dangerous in a production environment.

Debug messages can sometimes contain vital information for developing an attack, including:
- Values for key session variables that can be manipulated via user input
- Hostnames and credentials for back-end components
- File and directory names on the server
- Keys used to encrypt data transmitted via the client

Debugging information may sometimes be logged in a separate file. If an attacker is able to gain access to this file, it can serve as a useful reference for understanding the application's runtime state.

In the following lab, we find a debug file location inspecting the comments of a web page and we exfiltrate important information: [information_disclosure_comments](labs/information_disclosure_comments.md)

## User account pages
By their very nature, a user's profile or account page usually contains sensitive information, such as the user's email address, phone number, API key, and so on. As users normally only have access to their own account page, this does not represent a vulnerability in itself. However, some websites contain [logic flaws](https://portswigger.net/web-security/logic-flaws) that potentially allow an attacker to leverage these pages in order to view other users' data.

For example, consider a website that determines which user's account page to load based on a `user` parameter.

`GET /user/personal-info?user=carlos`

Most websites will take steps to prevent an attacker from simply changing this parameter to access arbitrary users' account pages. However, sometimes the logic for loading individual items of data is not as robust.

An attacker may not be able to load another users' account page entirely, but the logic for fetching and rendering the user's registered email address, for example, might not check that the `user` parameter matches the user that is currently logged in. In this case, simply changing the `user` parameter would allow an attacker to display arbitrary users' email addresses on their own account page.

## Source code disclosure via backup files
Source code of the application is very important to understand the application's behavior and construct high-severity attacks. Even sensitive data is often hard-coded within the source code (e.g., API keys or credentials for some services).

Ocasionally, it is even possible to cause the website to expose its own source code. When mapping out a website, you might find that some source code files are referenced explicitly. Unfortunately, requesting them does not usually reveal the code itself. When a server handles files with a particular extension, such as `.php`, it will typically execute the code, rather than simply sending it to the client as text. However, in some situations, you can trick a website into returning the contents of the file instead. For example, text editors often generate temporary backup files while the original file is being edited. 

These temporary files are usually indicated in some way, such as by appending a tilde (`~`) to the filename or adding a different file extension. Requesting a code file using a backup file extension can sometimes allow you to read the contents of the file in the response.

In the following lab, we try to disclose information by reading the backup source code: [information_disclosure_backup_files](labs/information_disclosure_backup_files.md) 

## Information disclosure due to insecure configuration
Websites are commonly misconfigured in some sections. This is specially common due to the usage of a lot of third-party libraries and technologies, whose have a big field of configuration options that are not well understood by the people that implement them.

In other cases, developers might forget to disable various debugging options in the production environment.
For example, the HTTP `TRACE` method is designed for diagnostic purposes. **If enabled, the web server will respond to requests that use the `TRACE` method by echoing in the response the exact request that was received.** This behavior is often harmless, but occasionally leads to information disclosure, such as the name of internal authentication headers that may be appended to requests by reverse proxies.

Here is a lab that consists in exploiting a webpage by sending a request with TRACE method and inspecting the headers received by the backend: [information_disclosure_http_trace_method](labs/information_disclosure_http_trace_method.md)

## Version control history
Virtually all websites are developed using some form of version control system, such as Git. By default, a Git project stores all of its version control data in a folder called `.git`. Occasionally, websites expose this directory in the production environment. In this case, you might be able to access it by simply browsing to `/.git`.

While it is often impractical to manually browse the raw file structure and contents, there are various methods for downloading the entire `.git` directory. You can then open it using your local installation of Git to gain access to the website's version control history. This may include logs containing committed changes and other interesting information

This might not give you access to the full source code, but comparing the diff will allow you to read small snippets of code. As with any source code, you might also find sensitive data hard-coded within some of the changed lines.

Here is a lab that covers the leaked information from a .git file: [information_disclosure_git_file](labs/information_disclosure_git_file.md)

# How to prevent information disclosure vulnerabilities
Preventing information disclosure completely is tricky due to the huge variety of ways in which it can occur. However, there are some general best practices that you can follow to minimize the risk of these kinds of vulnerability creeping into your own websites.

- Make sure that everyone involved in producing the website is fully aware of what information is considered sensitive. Sometimes seemingly harmless information can be much more useful to an attacker than people realize. Highlighting these dangers can help make sure that sensitive information is handled more securely in general by your organization.
- Audit any code for potential information disclosure as part of your QA or build processes. It should be relatively easy to automate some of the associated tasks, such as stripping developer comments.
- Use generic error messages as much as possible. Don't provide attackers with clues about application behavior unnecessarily.
- Double-check that any debugging or diagnostic features are disabled in the production environment.
- Make sure you fully understand the configuration settings, and security implications, of any third-party technology that you implement. Take the time to investigate and disable any features and settings that you don't actually need.