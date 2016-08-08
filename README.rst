poh: ssh commands runner
========================

Poh is a command runner over ssh, it can load commands from files or
from the command line, and the servers from stdin, or specified in the
command line as well.

It offers some output "prettifying" as well as raw outputs.

One of the features of this runner is that it should not require
anything other than one file and the python interpreter to run. This
guarantees that it can be transferred and used on remote servers that
don't have permissions for installing packages, or limited resources.

As such, it uses calls to the ssh binary rather than other more
idiomatic methods.

poh (including the poh repo, package, and related files) is licensed
under the `MIT license`_.


.. _MIT License: https://github.com/slashfoo/poh/blob/master/LICENSE.txt
