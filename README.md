# OverLINCS Git

![OLG logo](https://github.com/balouf/overlincs-git/blob/main/docs/olincs-logo.png?raw=true)

[![PyPI Status](https://img.shields.io/pypi/v/overlincs-git.svg)](https://pypi.python.org/pypi/overlincs-git)
[![Build Status](https://github.com/balouf/overlincs-git/actions/workflows/build.yml/badge.svg?branch=main)](https://github.com/balouf/overlincs-git/actions?query=workflow%3Abuild)
[![Documentation Status](https://github.com/balouf/overlincs-git/actions/workflows/docs.yml/badge.svg?branch=main)](https://github.com/balouf/overlincs-git/actions?query=workflow%3Adocs)
[![License](https://img.shields.io/github/license/balouf/overlincs-git)](https://github.com/balouf/overlincs-git/blob/main/LICENSE)
[![Code Coverage](https://codecov.io/gh/balouf/overlincs-git/branch/main/graphs/badge.svg)](https://codecov.io/gh/balouf/overlincs-git/tree/main)

[OverLincs Git](OLG) is a git-bridge for the [LINCS](LINCS) [Overleaf server](OL).

It allows to clone, push, and pull between a local repository and the [Overleaf server](OL).

Under the hood, [OverLincs Git](OLG) is an unofficial fork of the great
[python-sharelatex](SLX) module that has been patched for [Overleaf CE v4](OCE).


- Free software: GNU General Public License v3
- Documentation: https://balouf.github.io/overlincs-git/.


## Features

Provides a `olincs` CLI for interaction with the [LINCS](LINCS) [Overleaf server](OL).

- `olincs clone remote_url local_repo_name`
- `olincs pull`
- `olincs push`

## Credits

This package was created with [Cookiecutter][CC] and the [Package Helper 3][PH3] project template.

It is based on [python-sharelatex](SLX).

[CC]: https://github.com/audreyr/cookiecutter
[PH3]: https://balouf.github.io/package-helper-3/
[OCE]: https://github.com/overleaf/overleaf
[SLX]: https://gitlab.inria.fr/sed-rennes/sharelatex/python-sharelatex
[OL]: https://overleaf.lincs.fr
[OLG]: https://balouf.github.io/overlincs-git/
[LINCS]: https://www.lincs.fr/
