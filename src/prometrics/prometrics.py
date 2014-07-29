#!/usr/bin/python -OOBRtt
__doc__ = """Tool to measure project activity and quality.

Usage:
    prometrics repo [--dir-out=<OUT>] [--repo-dir=<DIR>] [--output-format=<FMT>] [--name=<NAME>] <PATH>
    prometrics list [--with-name] [--dir-out=<OUT>] [--repo-dir=<DIR>] [--output-format=<FMT>] <PATH>

Options:
    -d --dir-out=<OUT>          output directory [default: ./]
    -f --output-format=<FMT>    output-format [default: html5]
    --repo-dir=<DIR>            directory where store repository [default: /tmp/]
    --with-name
"""

from collections import namedtuple
from datetime import datetime
import multiprocessing as multip
import os
import pipes
import random
import shutil
import string
import tempfile

from docopt import docopt

import core
from core.git import GitCmdError
import repout


OUT2MAKER = {
    'html5': (repout.to_html5, repout.html5_index)
}

MAX_JOBS = 4


def log(msg):
    print "%s -> %s" % (datetime.now().isoformat(), msg)


def prepare_fname(name):
    return ''.join(ch.upper() for ch in name if ch.isalnum() or ch in '_ ').replace(' ', '_')


def random_string(n):
    return ''.join(random.choice(string.ascii_uppercase) for _ in xrange(n))


def launch(reporter, dir_tmp, dir_out, name, path):
    try:
        # clone
        log("cloning repository %r from %r" % (name, path))
        try:
            repo = core.Git.clone(path, dir_tmp)
        except GitCmdError, ex:
            log("ERROR: repository %r cloning repository : %r" % (name, str(ex)))
            raise
        try:
            # get info
            proj_out = os.path.join(dir_out, prepare_fname(name))
            if not os.path.exists(proj_out):
                os.mkdir(proj_out)
            for branch in repo.branches():
                try:
                    repo.branch = branch
                except GitCmdError, ex:
                    log("ERROR: repository %r switching to branch %r : %r" % (name, branch, str(ex)))
                    continue
                branch_out = os.path.join(proj_out, prepare_fname(branch))
                if not os.path.exists(branch_out):
                    os.mkdir(branch_out)
                log("reporting %r:%s" % (name, branch))
                try:
                    reporter(repo, dirpath=proj_out, project_name=name)
                except repout.ReportError, ex:
                    log("ERROR: repository %r reporting branch %r : %r" % (name, branch, str(ex)))
                    continue
        finally:
            log("removing repository %r at %r" % (name, repo.path))
            shutil.rmtree(repo.path)
    except KeyboardInterrupt:
        pass
    except (GitCmdError, repout.ReportError), ex:
        pass
    except Exception, ex:
        log("ERROR: repository %r %s: %r" % (name, ex.__class__.__name__, str(ex)))


def _prometrics():
    opts = docopt(__doc__)
    reporter, index_reporter = OUT2MAKER.get(opts['--output-format'], None)
    if reporter is None:
        log("ERROR: unknown output format %r" % opts['--output-format'])
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
        tmp_out = os.path.abspath(tempfile.mkdtemp(suffix='-repo', prefix='prometrics-%s-' % random_string(8), dir=opts['--repo-dir']))
        launch(reporter, tmp_out, dirout, name, opts['<PATH>'])
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
                tmp_out = os.path.abspath(tempfile.mkdtemp(suffix='-repo', prefix='prometrics-%s-' % random_string(8), dir=opts['--repo-dir']))
                args = reporter, tmp_out, dirout, name, path
                p = multip.Process(target=launch, args=args)
                p.start()
                procs[p.pid] = p, name
                index.append([name, tmp_out, path, os.path.join(dirout, prepare_fname(name))])
            else:
                for pid, (proc, name) in procs.items():
                    if not proc.is_alive():
                        procs.pop(pid, None)
                        log("end repository %r" % name)
        for l in index:
            l[1] = core.Git(l[1])
        index_reporter(dirout, index)
    else:
        return


if __name__ == '__main__':
    try:
        _prometrics()
    except KeyboardInterrupt:
        log("SIGINT interruption")
    except Exception, ex:
        log("Error: %r" % str(ex))
