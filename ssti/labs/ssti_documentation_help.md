With the account they give, we can see some kind of templating:
![](imgs/ssti_documentation_help.png)

We don't know the templating framework, but we can try some things more:
![](imgs/ssti_documentation_help-1.png)

I have learned from this lab that sometimes triggering an error can leads us to the leak of the framework (which is useful information):
![](imgs/ssti_documentation_help-2.png)

Reading the documentation of this framework, we can see the following section:
![](imgs/ssti_documentation_help-3.png)

We can see that the `new()` item is insecure:
![](imgs/ssti_documentation_help-4.png)

It allows creating an arbitrary java object by creating object that implement `TemplateModel`interfaces.

Reading in the `new` documentation, we can see more about its usage and implications:![](imgs/ssti_documentation_help-5.png)

Reading the documentation of the `TemplateModel` interface, we see which classes do implement this interface:
https://freemarker.apache.org/docs/api/freemarker/template/TemplateModel.html
![](imgs/ssti_documentation_help-6.png)

We must look for a class that allows us executing commands. There is a class called `Execute`:
![](imgs/ssti_documentation_help-7.png)

![](imgs/ssti_documentation_help-8.png)


We must combine the constructor of this method next to the creation of a `new` TemplateModel:
`<#assign ex="freemarker.template.utility.Execute"?new()> ${ ex("rm /home/carlos/morale.txt") }`

This way we use the `new` function, which is the insecure function of the templating, and we call one of the subclasses of the `TemplateModel` class, which is `Execute` and then we just use this variable to execute commands, once the variable is created in the templating framework.
![](imgs/ssti_documentation_help-9.png)
