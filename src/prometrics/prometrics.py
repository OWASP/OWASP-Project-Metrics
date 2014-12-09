#!/usr/bin/python -OOBtt
__doc__ = """Tool to measure project activity and quality.

Usage:
    prometrics list [--dir-out=<OUT>] [--repo-dir=<DIR>] [<PATH>]

Options:
    -d --dir-out=<OUT>  output directory [default: ./]
    --repo-dir=<DIR>    directory where store repository [default: /tmp/]
"""

from datetime import datetime
from docopt import docopt
import fcntl
import os
import os.path
import logging
import subprocess
import random
import select
import shutil
import signal
import string
import sys
import tempfile
import time
from StringIO import StringIO

from core.git import Git, GitError
import repout

MAX_JOBS = 8


log = logging.getLogger('prometrics')
log.setLevel(logging.DEBUG)
hdl = logging.StreamHandler(sys.stdout)
fmt = logging.Formatter('%(levelname)s :: %(name)s :: %(asctime)s -> %(message)s')
hdl.setFormatter(fmt)
log.addHandler(hdl)


def random_string(n):
    return ''.join(random.choice(string.ascii_uppercase) for _ in xrange(n))


def normalize_name(name):
    return ''.join(ch.upper() for ch in name if ch.isalnum() or ch in '_. ').replace(' ', '_').replace('.', '_').replace('/', '_')


def read_and_write(proc, out):
    if proc.returncode is None:
        try:
            buf = proc.stdout.read(1024)
        except (IOError, ValueError):
            return
        last_eol = buf.rfind('\n')
        if last_eol == -1:
            out.write(buf)
        else:
            sys.stdout.write(out.getvalue())
            sys.stdout.write(buf[:last_eol+1])
            out.truncate(0)
            out.seek(0)
            out.write(buf[last_eol+1:])
    else:
        out, err = proc.communicate()
        sys.stdout.write(out)
        if out[-1] != '\n':
            sys.stdout.write('\n')


def _prometrics():
    opts = docopt(__doc__)
    out_dir = os.path.abspath(opts['--dir-out'])
    if not os.path.exists(out_dir):
        os.mkdir(out_dir)
    with open(opts['<PATH>'] or './list.txt', 'rb') as fl:
        todo = [line.strip().rpartition(';')[::2] for line in fl if line.strip()]
    wip = {}
    done_repos = []
    log.info("start prometrics")
    try:
        while todo or wip:
            if todo and len(wip) < MAX_JOBS:
                name, origin = todo.pop(0)
                tmp_dir = os.path.abspath(tempfile.mkdtemp(suffix='-repo', prefix='prometrics-%s-' % random_string(8), dir=opts['--repo-dir']))
                # create subprocess for report
                repo_out_dir = os.path.join(out_dir, normalize_name(name))
                if not os.path.exists(repo_out_dir):
                    os.mkdir(repo_out_dir)
                p = subprocess.Popen(('./prometrics-report.py', name, origin, tmp_dir, repo_out_dir), stderr=subprocess.PIPE, stdout=subprocess.PIPE)
                log.info("start process [%d] report repository %r from %r", p.pid, name, origin)
                wip[p.pid] = p, name, origin, tmp_dir, StringIO()
                fd = p.stdout.fileno()
                fl = fcntl.fcntl(fd, fcntl.F_GETFL)
                fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)
                # time.sleep(3)
            else:
                for pid, (proc, name, origin, tmp_dir, buf) in wip.items():
                    proc.poll()
                    rc = proc.returncode
                    if rc is not None:
                        out, err = proc.communicate()
                        sys.stdout.write('%s%s' % (buf.getvalue(), out))
                        if rc:
                            log.error("end process with error process [%d] report repository %r from %r:\n%s", proc.pid, name, origin, err)
                        else:
                            log.info("end process [%d] report repository %r from %r: success", proc.pid, name, origin)
                        wip.pop(pid, None)
                        done_repos.append(name)
                    else:
                        read_and_write(proc, buf)
    finally:
        for pid, (proc, name, _, tmp_dir, buf) in wip.iteritems():
            os.kill(pid, signal.SIGINT)
            read_and_write(proc, buf)
            shutil.rmtree(tmp_dir, 1)
    repos = []
    for name in done_repos:
        repo_out = os.path.join(out_dir, normalize_name(name))
        bls = os.path.join(repo_out, 'branches.txt')
        branches = []
        if not os.path.exists(bls):
            continue
        with open(bls, 'rb') as fl:
            for line in fl.read().split('\n'):
                line = line.strip()
                if line:
                    branches.append(line)
        if branches:
            repos.append((name, branches, repo_out))
    log.info("report index")
    repout.html5_index(out_dir, repos)
    log.info("end prometrics")


if __name__ == '__main__':
    try:
        _prometrics()
    except KeyboardInterrupt:
        log.error("SIGINT interruption")
        sys.exit(100)
    except Exception, ex:
        import traceback
        traceback.print_exc()
        log.critical(str(ex))
        
            
        
    
