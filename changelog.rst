Changelog
===========


3.0.0
-----

- Added support for https://overleaf.irisa.fr
- Introduce authentication methods
    - https://sharelatex.irisa.fr -- `legacy` authentication method
    - https://overleaf.irisa.fr -- `igrida` authentication method
    - Overleaf CE (3.0.1) --  `community` authentication method
- Optimize pull/push operation by requesting only file that needs to be updated
  (based on time comparisons between your local machine and the remote server)
- Use persitent sessions by default (avoid to log in for every single requests)

0.5.2
-----

- Cli/push: ``--force`` is now a flag

0.5.2
-----

- Cli/clone: Add a check for the base_url format

0.5.1
-----

- Add version in the user agent

0.5.0
-----

- Client: (transparent) support for `raweb-latex.inria.fr`
- Misc: Add some functionnal tests

0.4.0
-----

- Client: add ``new`` method to create a template project
- Client: add ``delete`` method to delete a project
- Client: use a custom user-agent: ``python-sharelatex``
- Cli: expose  ``--https-cert-check/--no-https-cert-check`` to control whether    ssl verification must be done
- Misc: cleaning and initial functional tests

0.3.0
-----

- Passwords are now stored in the keyring system

0.2.1
-----

- Doc: some fixes/additions

0.2.0
-----

- First version of share project fonctions

0.1.1
-----

- Fails early in case of wrong credentials

0.1.0
-----

- First public release: clone, new, pull, push available in the cli
