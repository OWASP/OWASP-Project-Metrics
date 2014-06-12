# This file is part of Foobar.
#
#    OWASP Project Metrics is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    Foobar is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with OWASP Project Metrics.  If not, see <http://www.gnu.org/licenses/>.
"""Class to represent a Git Repository"""
import os.path
import subprocess as subp
from functools import partial


class GitError(Exception):
    pass


class GitCmdError(GitError):

    def __init__(self, code, stderr):
        self.code = int(code)
        self.stderr = str(stderr)

    def __str__(self):
        return '<GitCmdError: [%d] %s>' \
               % (self.code, self.stderr.encode('string-escape'))


__all__ = 'Git',


BUFSIZE = 4096
EOL = '\n'


def git_cmd(git, path, *args):
    p = subp.Popen((git, '--git-dir=%s' % path) + args,
                   stdout=subp.PIPE, stderr=subp.PIPE)
    buf = p.stdout.read(BUFSIZE)
    eol_len = len(EOL)
    try:
        while buf:
            eol = buf.find(EOL)
            if eol < 0:
                _buf = p.stdout.read(BUFSIZE)
                if not buf:
                    yield buf
                    raise StopIteration
                buf = '%s%s' % (buf, _buf)
                del _buf
            else:
                yield buf[:eol]
                buf = buf[eol + eol_len:]
                if not buf:
                    buf = p.stdout.read(BUFSIZE)
    finally:
        _, stderr = p.communicate()
        if p.returncode:
            raise GitCmdError(p.returncode, stderr)


class Git(object):

    def __init__(self, path, git='git'):
        self.git = partial(git_cmd, str(git), os.path.abspath(path))
        # test the repository
        self.git('log')

