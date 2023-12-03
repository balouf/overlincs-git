# Using OverLINCS Git

[Overleaf Community Edition][OCE] doesn't provide native Git-like functionalities,
but Irisa has built a nice [Git bridge][SLX] from which [OverLincs Git][OLG] builds upon.

The idea is to have a regular git installed locally,
with an emulation of a remote git provided by the bridge.

In short:

- Use `olincs` instead of `git` for `clone`, `push`, and `pull`, i.e. all remote interactions.
- Use `git` for `commit` and `add`, i.e. purely local updates.
- `git rm` is not fully supported. File deletion should be performed directly on [OverLincs][OL].
- As a general rule, other commands should be avoided, OverLincs Git only addresses the basic pull/commit/push cycle.

Note: you can also use `git olincs clone/pull/push` if you prefer.

## Cloning an OverLincs repository

```console
$ olincs clone REMOTE_URL LOCAL_DIRECTORY
```

For example:

```console
$ olincs clone https://overleaf.lincs.fr/project/6568a676f421bb1300173f2c mydir
```

## Retrieve remote changes

Inside your local repository:

```console
$ olincs pull
```

If you end up with conflicts, you'll have to resolve them manually, like in a regular git.

## Upload local changes

### Add files

Add files with `git add`:

```console
$ git add nice_picture.png
```

```console
$ git add *.bib
```

### Remove files

Don't. Remove files on server side and do `olincs pull`.

### Commit changes

Commit files with `git commit`, e.g.:

```console
$ git commit -a -m "Modification description"
```

### Push

```console
$ olincs push
```

Note that [OverLincs Git][OLG] automatically performs a `pull` before `pushing` so you do not need to do it manually.



[OCE]: https://github.com/overleaf/overleaf
[SLX]: https://gitlab.inria.fr/sed-rennes/sharelatex/python-sharelatex
[OL]: https://overleaf.lincs.fr
[OLG]: https://balouf.github.io/overlincs-git/
