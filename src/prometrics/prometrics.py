#!/usr/bin/python -OOBRtt
from collections import namedtuple
from datetime import datetime
import os
import tempfile

from docopt import docopt

import core
import repout

__doc__ = """Tool to measure project activity and quality.

Usage:
    prometrics repo [--dir-out=<OUT>] [--output-format=<FMT>] [--name=<NAME>] <PATH>
    prometrics list [--with-name] [--dir-out=<OUT>] [--output-format=<FMT>] <PATH>

Options:
    -d --dir-out=<OUT>          output directory [default: ./]
    -f --output-format=<FMT>    output-format [default: html5]
    --with-name                 <name>, <path>
"""

TMP = '/tmp/'
PREFIX_LOG = '  +'


OUT2MAKER = {
    'html5': repout.to_html5
}


def _prometrics():
    opts = docopt(__doc__)
    reporter = OUT2MAKER.get(opts['--output-format'], None)
    if reporter is None:
        print "Error: unknown output format %r" % opts['--output-format']
        return 1
    if opts['repo']:
        name = opts['--name']
        if name is None:
            name = os.path.split(opts['<PATH>'])[1]
            if name.endswith('.git'):
                name = name[:-4]
        paths = (name, opts['<PATH>']),
    elif opts['list']:
        def read_paths(path):
            with open(path, 'rb') as fl:
                if opts['--with-name']:
                    for line in fl:
                        name, _, path = line.strip().partition(';')
                        yield name, path
                else:
                    for line in fl:
                        yield line.strip()
        paths = read_paths(opts['<PATH>'])
    #
    dirout = os.path.abspath(opts['--dir-out'])
    if not os.path.exists(dirout):
        os.mkdir(dirout)
    #
    for name, path in paths:
        print "Repository: %r" % path
        # tmp
        print PREFIX_LOG, "making temporary folder..."
        dir_out = os.path.abspath(tempfile.mkdtemp(suffix='-repo', prefix='prometrics-', dir=TMP))
        # XXX
        os.chdir(dir_out)
        # clone
        print PREFIX_LOG, "cloning repository..."
        repo = core.Git.clone(path, dir_out)
        # get info
        proj_out = os.path.join(dirout, name)
        if not os.path.exists(proj_out):
            os.mkdir(proj_out)
        print PREFIX_LOG, "printing repository's report..."
        for branch in repo.branches():
            print ' ' * len(PREFIX_LOG), '    -', branch
            repo.branch = branch
            branch_out = os.path.join(proj_out, branch)
            if not os.path.exists(branch_out):
                os.mkdir(branch_out)
            reporter(repo, dirpath=proj_out, project_name=name)


if __name__ == '__main__':
    _prometrics()
