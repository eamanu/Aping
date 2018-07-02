# Contribute

If you have some comments, suggestions please feel free to send a e-mail to:

1. The author personal e-mail address: kantorzsolt@yahoo.com or
2. The maintainer personal e-mail address: emmanuelarias30@gmail.com

---

# Issues

The issues must include a [short, self contained, correct example] (http://sscce.org/). It is very useful for us and other developer if you send an issue with, for example, a copy-paste of the issue or exception, and with the neccessary information that we and other developer could reproduce the issue.

Before send a issue, you shall be sure that the issue don't exist currently.

Please, to send a issue go [here](https://github.com/eamanu/Aping/issues)

---

# Pull Requests

First, follow the [KISS](https://en.wikipedia.org/wiki/KISS_principle) principle. Is better test and merge a small and controllable PR than and big and uncontrollable PR. So, please don't try to make big changes and try to solve one issue or create one feature per each PR.

To make a PR, please, create a branch based on the *develop* branch for each feature added or bug solved. Don't try to solve lot of bugs for PR.

It will great if you add a new feature uses the prefix `feature`, i.e. `feature/new-feature-abc`. If you fix some issue, it will great you uses the prefix `fix` with a reference of the issue, i.e. `fix/issue-#number`. 

I leave here some references that personally I like, about how to write good commits message:

1. http://who-t.blogspot.com/2009/12/on-commit-messages.html 
2. https://tbaggery.com/2008/04/19/a-note-about-git-commit-messages.html
3. http://365git.tumblr.com/post/3308646748/writing-git-commit-messages

You could send your PR from [here](https://github.com/eamanu/Aping/pulls)

# Coding conventions

Aping try to follows pep8 [Style Guide for Python Code](https://www.python.org/dev/peps/pep-0008/) except for line length. Please check your code with pep8 Python style guide checker, by running `pep8 --ignore=E501 github`.