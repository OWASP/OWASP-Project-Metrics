#!/usr/bin/python -OOBRtt
from collections import namedtuple
from datetime import datetime
import multiprocessing as multip
import os
import pipes
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

OUT2MAKER = {
    'html5': (repout.to_html5, repout.html5_index)
}

MAX_JOBS = 4


def launch(reporter, dir_tmp, dir_out, name, path):
    try:
        # clone
        print "cloning repository %r" % name
        repo = core.Git.clone(path, dir_tmp)
        # get info
        proj_out = os.path.join(dir_out, name)
        if not os.path.exists(proj_out):
            os.mkdir(proj_out)
        for branch in repo.branches():
            repo.branch = branch
            branch_out = os.path.join(proj_out, branch)
            if not os.path.exists(branch_out):
                os.mkdir(branch_out)
            print "reporting %r:%s" % (name, branch)
            reporter(repo, dirpath=proj_out, project_name=name)
    except:
        pass


def _prometrics():
    opts = docopt(__doc__)
    reporter, index_reporter = OUT2MAKER.get(opts['--output-format'], None)
    if reporter is None:
        print "Error: unknown output format %r" % opts['--output-format']
        return 1
    dirout = os.path.abspath(opts['--dir-out'])
    if not os.path.exists(dirout):
        os.mkdir(dirout)
    if opts['repo']:
        name = opts['--name']
        if name is None:
            name = os.path.split(opts['<PATH>'])[1]
            if name.endswith('.git'):
                name = name[:-4]
        report_repo(reporter, name, opts['<PATH>'], dirout)
    elif opts['list']:
        queue = []
        procs = {}
        index = []
        with open(opts['<PATH>'], 'rb') as fl:
            if opts['--with-name']:
                for line in fl:
                    line = line.strip()
                    if not line:
                        continue
                    name, _, path = line.strip().partition(';')
                    queue.append((name, path))
            else:
                for line in fl:
                    name = os.path.split(opts['<PATH>'])[1]
                    if name.endswith('.git'):
                        name = name[:-4]
                    queue.append((name, path))
        while queue or procs:
            if queue and len(procs) < MAX_JOBS:
                name, path = queue.pop(0)
                tmp_out = os.path.abspath(tempfile.mkdtemp(suffix='-repo', prefix='prometrics-', dir=TMP))
                args = reporter, tmp_out, dirout, name, path
                p = multip.Process(target=launch, args=args)
                p.start()
                procs[p.pid] = p, name
                index.append([name, tmp_out, path, os.path.join(dirout, name)])
            else:
                for pid, (proc, name) in procs.items():
                    if not proc.is_alive():
                        procs.pop(pid, None)
                        print "end repository %r" % name
        for l in index:
            l[1] = core.Git(l[1])
        index_reporter(dirout, index)
    else:
        return


if __name__ == '__main__':
    try:
        _prometrics()
    except KeyboardInterrupt:
        print "SIGINT interruption"
    except Exception, ex:
        print "Error: %r" % str(ex)
