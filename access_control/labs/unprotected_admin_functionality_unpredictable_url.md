# Lab description
This lab is the continuation of [[unprotected_admin_functionality]] which adds a point in which the URL is not in the robots.txt file, but in the source code of the application. Therefore, the URL is not predictable, but the code can be analyzed in order to obtain it as the server leaks this endpoint info.

# Writeup
Visit the website and CTRL+U to see the source code of the appliaction. There is a JavaScript code that is checking if we are admin, and if we are admin, it inserts the bar to visit the admin panel. Therefore, in this code, there is a **leaked URL to the admin panel:**
![[imgs/unprotected_admin_functionality_unpredictable_url.png]]

Visiting this endpoint leads us to the admin panel and we can delete the user carlos:
![[imgs/unprotected_admin_functionality_unpredictable_url-1.png]]

