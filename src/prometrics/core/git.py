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
from collections import namedtuple
from functools import partial
import os.path
import subprocess as subp


NULL_HASH = '0' * 40


class GitError(Exception):
    pass


class GitFormatError(GitError):
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


Commit = namedtuple('Commit', ('hash', 'tree', 'parent',
                    'author_name', 'author_email', 'author_date',
                    'commiter_name', 'commiter_email', 'commiter_date',
                    'subject', 'text'))


IN_INFO = 1
IN_DATA = 2


class Git(object):

    def __init__(self, path, git='git'):
        self.git_out = partial(git_cmd, str(git), os.path.abspath(path))
        def git_ignore_out(*args):
            for _ in self.git_out(*args):
                pass
        self.git_cmd = git_ignore_out

    @property
    def branch(self):
        for line in self.git_out('branch', '--list', '--all'):
            if line[0] == '*':
                line = line.lstrip('* ').rstrip()
                return line.rpartition(' -> ')[2].rpartition('/')[2]
        return None

    @branch.setter
    def branch(self, name):
        if name not in self.branches():
             raise GitError("unknown branch: %r" % name)
        self.git_cmd('checkout', name)

    def branches(self):
        bs = set()
        for line in self.git_out('branch', '--list', '--all'):
            line = line.lstrip('* ').rstrip()
            if ' -> ' in line:
                continue
            _, _, bname = line.rpartition('/')
            bs.add(bname)
        return bs

    def commits(self):
        in_data = 0
        fields = None
        text = []
        for line in self.git_out('log', '-B', '-M20', '-C', '-l9999','--find-copies-harder',
                                 '--pretty=format:%x00%H%x00%T%x00%P%x00%an%x00%ae%x00%ai%x00%cn%x00%ce%x00%ci%x00%s%x00',
                                 '--pickaxe-all', '--summary'):
            if in_data:
                if line.startswith('\0'):
                    yield Commit(*(tuple(fields[1:-1]) + ('\n'.join(text),)))
                    fields = None
                    text = []
                    in_data = 0
                else:
                    text.append(line)
            if not in_data:
                fields = line.split('\x00')
                if len(fields) != 12:
                    raise GitFormatError("invalid line %r" % line)
                in_data = 1
        if fields and text:
            yield Commit(*(tuple(fields[1:-1]) + ('\n'.join(text),)))

    def short2long_hash(self, short):
        return NULL_HASH if len(short) >= 10 and all(ch == '0' for ch in short) \
               else self.git_out('rev-parse', '--verify', short).next().strip()

