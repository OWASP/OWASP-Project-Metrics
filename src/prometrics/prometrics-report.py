#!/usr/bin/python -OOBtt
import logging
import os
from core.git import Git, GitError
import repout
import shutil
import sys

log = logging.getLogger('prometrics-report')
log.setLevel(logging.DEBUG)
hdl = logging.StreamHandler(sys.stdout)
fmt = logging.Formatter('%(levelname)s :: %(name)s :: %(asctime)s -> %(message)s')
hdl.setFormatter(fmt)
log.addHandler(hdl)


def _main():
    name, origin, tmp_dir, out_dir = sys.argv[1:5]
    log.info("[%r] start report", name)
    try:
        if not os.path.exists(tmp_dir):
            os.mkdir(tmp_dir)
        try:
            log.info("[%r] clone repository %r", name, origin)
            repo = Git.clone(origin, tmp_dir)
        except GitError, ex:
            log.error("[%r] clone repository %r >> %r", name, origin, str(ex))
            return
        try:
            log.info("[%r] clean repository", name)
            repo.clean()
        except GitError, ex:
            log.error("[%r] clean repository >> %r", name, str(ex))
            return
        done_branches = []
        for branch in repo.branches():
            try:
                log.info("[%r] report repository %r switching to branch %r", name, origin, branch)
                repo.branch = branch
            except GitError, ex:
                log.error("[%r] report repository %r switching to branch %r >> %r", name, origin, branch, str(ex))
                continue
            log.info("[%r] report html5 repository %r branch %r" % (name, origin, branch))
            try:
                repout.to_html5(repo, dirpath=out_dir, project_name=name)
                done_branches.append(branch)
            except repout.ReportError, ex:
                log.error("[%r] report html5 repository %r branch %r >> %r", name, origin, branch, str(ex))
                continue
            log.info("[%r] end report html5 repository %r branch %r", name, origin, branch)
        if done_branches:
            with open(os.path.join(out_dir, 'branches.txt'), 'wb') as fl:
                for branch in done_branches:
                    fl.write(branch)
                    fl.write('\n')
    finally:
        shutil.rmtree(tmp_dir, 1)

if __name__ == '__main__':
    _main()

