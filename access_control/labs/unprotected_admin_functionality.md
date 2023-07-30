# Lab description
This lab covers the [../main > Unprotected functionality](../access_control.md#Unprotected%20functionality) section.


# Writeup
This writeup is simple. There is no protection in the administration panel, but we have to look for it.
We just visit `robots.txt` of the website and see that there is an endpoint called  `administrator-panel`:

![](imgs/unprotected_admin_functionality.png)\

Visitng this endpoint leads us to the admin functionality, which is unprotected. Just delete the user carlos:

![](imgs/unprotected_admin_functionality-1.png)

![](imgs/unprotected_admin_functionality-2.png)

