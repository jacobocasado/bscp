We just visit the `/.git` folder and we can see that we have access to it:
![](imgs/information_disclosure_git_file.png)

Let's inspect the `<logs>` section, that tells us that the admin password has been removed from `config`:
![](imgs/information_disclosure_git_file-1.png)

We can see in `config` that the password does not exist:
![](imgs/information_disclosure_git_file-2.png)

Let's download the whole .git folder and use the git commands to see the log of the commits and then check the information of the commit changes:
![](imgs/information_disclosure_git_file-3.png)

We can see the leaked admin password and we can log in and delete carlos:
![](imgs/information_disclosure_git_file-4.png)

