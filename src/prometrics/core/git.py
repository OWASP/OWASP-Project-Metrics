# This file is part of WASP Project Metrics.
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
from datetime import datetime, tzinfo
from functools import partial
import hashlib
import os.path
import random
import subprocess as subp
import string
import tempfile


NULL_HASH = '0' * 40


STATUS_ADD = 'A'
STATUS_COPY = 'C'
STATUS_DELETE = 'D'
STATUS_MODIFICATION = 'M'
STATUS_RENAME = 'R'
STATUS_CHANGE_TYPE = 'T'
STATUS_UNMERGED = 'U'
STATUS_UNKNOWN = 'X'


class GitError(Exception):
    pass


class GitFormatError(GitError):
    pass


class GitCmdError(GitError):

    def __init__(self, cmd, code, stderr):
        self.cmd = tuple(cmd)
        self.code = int(code)
        self.stderr = str(stderr)

    def __repr__(self):
        return '<GitCmdError: [%d] %s by %r>' \
               % (self.code, self.stderr.encode('string-escape'), self.cmd)

    def __str__(self):
        return 'Git Error [%d] %s by %r' \
               % (self.code, self.stderr.encode('string-escape'), self.cmd)


class NeedUsernamePassword(GitCmdError):
    pass


class UnreachableObject(GitCmdError):

    def __init__(self, obj):
        self.obj = str(obj)
    
    def __str__(self):
        return "Git Error [%d] object %r is unreachable" % self.obj


def raise_git_error(cmd, code, stderr):
    if stderr.endswith('Needed a single revision\n'):
        raise UnreachableObject(cmd[-1])
    raise GitCmdError(cmd, code, stderr)


__all__ = 'Git',


BUFSIZE = 4096
EOL = '\n'


def clone(git, repo, out):
    if repo[:8] == 'https://':
        repo = 'https://git::@%s' % repo[8:]
    if repo[:9] == 'https://':
        repo = 'http://git::@%s' % repo[8:]
    cmd = git, 'clone', repo, out
    p = subp.Popen(cmd, stdout=subp.PIPE, stderr=subp.PIPE)
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
                if 'Username for' in buf:
                    raise NeedUsernamePassword("need login for repository %r" % repo)
                yield buf[:eol]
                buf = buf[eol + eol_len:]
                if not buf:
                    buf = p.stdout.read(BUFSIZE)
    finally:
        _, stderr = p.communicate()
        if p.returncode:
            raise GitCmdError(cmd, p.returncode, stderr)


def git_cmd(git, path, *args):
    # print "RUN CMD: %r" % ((git, '--git-dir=%s' % os.path.join(path, '.git'), '--work-tree=%s' % path) + args,)
    cmd = git, '--git-dir=%s' % os.path.join(path, '.git'), '--work-tree=%s' % path
    cmd += args
    p = subp.Popen(cmd, stdout=subp.PIPE, stderr=subp.PIPE)
    buf = p.stdout.read(BUFSIZE)
    eol_len = len(EOL)
    try:
        while buf:
            eol = buf.find(EOL)
            if eol < 0:
                _buf = p.stdout.read(BUFSIZE)
                if not _buf:
                    yield buf.decode('utf-8', errors='replace')
                    raise StopIteration
                buf = '%s%s' % (buf, _buf)
                del _buf
            else:
                yield buf[:eol].decode('utf-8', errors='replace')
                buf = buf[eol + eol_len:]
                if not buf:
                    buf = p.stdout.read(BUFSIZE)
    finally:
        _, stderr = p.communicate()
        if p.returncode:
            raise_git_error(cmd, p.returncode, stderr)


def rename2files(rename):
    oc_pos = rename.find('{')
    cc_pos = rename.find('}')
    ar_pos = rename.find(' => ')
    if oc_pos >= 0 and cc_pos > oc_pos and (oc_pos < ar_pos < cc_pos):
        prefix = rename[:oc_pos]
        postfix = rename[cc_pos + 1:]
        src, _, dst = rename.partition(' => ')
        return src, dst
    return rename, rename


Commit = namedtuple('Commit', ('hash', 'tree', 'parent',
                    'author_name', 'author_email', 'author_date',
                    'commiter_name', 'commiter_email', 'commiter_date',
                    'subject', 'text'))

Change = namedtuple('Change', ('commit', 'src_mode', 'src_hash', 'dst_mode',
                    'dst_hash', 'status', 'percentage', 'src_file', 'dst_file'))

Stat = namedtuple('Stat', ('commit', 'src_file', 'dst_file', 'add', 'rm'))

File = namedtuple('File', ('hash', 'mode', 'name', 'type'))

Object = namedtuple('Object', ('id', 'lines', 'sha1', 'sha256', 'sha512', 'raw'))


IN_INFO = 1
IN_DATA = 2


is_invalid = lambda fields: None in fields

def restore_commit(cmt, last):
    if cmt[5] is None:
        cmt[5] = last.author_date
    if cmt[8] is None:
        cmt[8] = last.commiter_date
    return Commit(*cmt)


class Git(object):

    def __init__(self, path, git='git'):
        self.path = os.path.abspath(path)
        self.git_out = partial(git_cmd, str(git), self.path)
        def git_ignore_out(*args):
            for _ in self.git_out(*args):
                pass
        self.git_cmd = git_ignore_out
        self._branches = {}

    @staticmethod
    def clone(path, out='./', git='git'):
        out = os.path.abspath(out)
        for line in clone(git, path, out):
            pass
        return Git(out)

    def clean(self):
        for line in self.git_out('reflog', 'expire', '--expire-unreachable=now', '--all'):
            pass
        for line in self.git_out('gc', '--prune=now'):
            pass
        for line in self.git_out('fsck', '--full', '--unreachable', '--strict', '--dangling', '--no-reflogs'):
            pass

    @property
    def branch(self):
        branches = {v: k for k, v in self._branches.iteritems()}
        for line in self.git_out('branch', '--list', '--all'):
            if line[0] == '*':
                line = line.lstrip('* ').rstrip()
                name = line.rpartition(' -> ')[2].replace('_', '/')
                return branches.get(name, name)
        return None

    @branch.setter
    def branch(self, name):
        if name not in self.branches():
             raise GitError("unknown branch: %r" % name)
        self.git_cmd('remote', 'update')
        self.git_cmd('fetch')
        if name in self._branches:
            local_name = self._branches[name]
        else:
            local_name = self._branches[name] = ''.join(random.choice(string.ascii_letters) for _ in xrange(16))
        try:
            self.git_cmd('checkout', '-b', local_name, name)
        except GitError, ex:
            try:
                self.git_cmd('checkout', name)
            except GitError:
                raise ex

    def branches(self):
        bs = set()
        for line in self.git_out('branch', '--list', '--all', '-r'):
            name = line.lstrip('* ').rstrip()
            if not line:
                continue
            if ' -> ' in name:
                continue
            bs.add(name)
        return bs

    def commits(self):
        in_data = 0
        fields = None
        text = []
        last = None
        no_date = []
        for line in self.git_out('log', '-B', '-M20', '-C', '-l9999','--find-copies-harder', '--pretty=format:%x00%H%x00%T%x00%P%x00%an%x00%ae%x00%ai%x00%cn%x00%ce%x00%ci%x00%s%x00', '--pickaxe-all', '--summary'):
            if in_data:
                if line.startswith('\0'):
                    fields = fields[1:-1]
                    fields.append('\n'.join(text))
                    if is_invalid(fields):
                        no_date.append(fields)
                    else:
                        if last:
                            while no_date:
                                c = no_date.pop()
                                yield restore_commit(c, last)
                        last = Commit(*fields)
                        yield last
                    fields = None
                    text = []
                    in_data = 0
                else:
                    text.append(line)
            if not in_data:
                fields = line.split('\x00')
                if len(fields) != 12:
                    raise GitFormatError("invalid line %r" % line)
                if fields[6]:
                    dt, _, tz = fields[6].rpartition(' ')
                    # TODO set timezone
                    fields[6] = datetime.strptime(dt, '%Y-%m-%d %H:%M:%S')
                else:
                    fields[6] = None
                if fields[9]:
                    dt, _, tz = fields[9].rpartition(' ')
                    # TODO set timezone
                    fields[9] = datetime.strptime(dt, '%Y-%m-%d %H:%M:%S')
                else:
                    fields[9] = None
                in_data = 1
        if fields:
            fields = fields[1:-1]
            fields.append('\n'.join(text))
            if is_invalid(fields):
                no_date.append(fields)
            else:
                if last:
                    while no_date:
                        c = no_date.pop()
                        yield restore_commit(c, last)
                last = Commit(*fields)
                yield last
        if last:
            while no_date:
                c = no_date.pop()
                yield restore_commit(c, last)

    def short2long_hash(self, short):
        return NULL_HASH if len(short) >= 7 and all(ch == '0' for ch in short) \
               else self.git_out('rev-parse', '--verify', short).next().strip()

    def changes(self):
        in_data = 0
        for line in self.git_out('whatchanged', '-B', '-M20', '-C', '-l9999',
                                 '--find-copies-harder', '--pickaxe-all',
                                 '-r', '--pretty=format:%x00%H%x00'):
            if not line:
                continue
            if line.startswith('\0'):
                commit = line.split('\0')[1]
            else:
                fields = line.split(' ')
                src_mode, dst_mode, src_hash, dst_hash = fields[:4]
                finfo = ' '.join(fields)
                src_hash = self.short2long_hash(src_hash.rstrip('.'))
                dst_hash = self.short2long_hash(dst_hash.rstrip('.'))
                status, _, files = finfo.partition('\t')
                status = status[0]
                perc = status[1:] or None
                #
                if status == STATUS_ADD:
                    src_file = None
                    dst_file = files
                elif status == STATUS_DELETE:
                    src_file = files
                    dst_file = None
                elif status in (STATUS_MODIFICATION, STATUS_CHANGE_TYPE):
                    src_file = dst_file = files
                elif status in (STATUS_RENAME, STATUS_COPY, STATUS_UNMERGED):
                    src_file, dst_file = files.split('\t')
                else:
                    continue
                yield Change(commit, src_mode.lstrip(':'), src_hash, dst_mode.lstrip(':'), dst_hash, status, perc, src_file, dst_file)

    def stats(self):    
        for line in self.git_out('log', '-B', '-M20', '-C', '-l9999', '--numstat',
                                 '--find-copies-harder', '--pickaxe-all',
                                 '-r', '--pretty=format:%x00%H%x00'):
            if not line:
                continue
            if line.startswith('\0'):
                commit = line.split('\0')[1]
            else:
                add, rm, fname = line.split('\t')
                src, dst = rename2files(fname)
                yield Stat(commit, src, dst,
                           int(add) if add.isdigit() else 0,
                           int(rm) if rm.isdigit() else 0)

    @property
    def trees(self):
        for line in self.git_out('rev-list', '--all'):
            yield line.strip()

    def files(self, where=None):
        for line in self.git_out('ls-tree', '-r', self.branch if where is None else str(where)):
            fields = line.split(' ')
            mode, otype = fields[:2]
            ohash, oname = ' '.join(fields[2:]).split('\t')
            yield File(ohash, mode, oname, otype)

    def blobs(self, tree):
        tree = str(tree)
        if tree not in tuple(self.trees):
            raise GitError("unknown tree %r" % tree)
        for f in self.files(tree):
            if f.otype == 'blob':
                yield f

    def object(self, commit, file, out=None):
        lines = 0
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()
        sha512 = hashlib.sha512()
        for line in self.git_out('show', '%s:%s' % (commit, file)):
            lines += 1
            line = '%s%s' % (line, EOL)
            if out:
                out.write(line)
            sha1.update(line)
            sha256.update(line)
            sha512.update(line)
        obj_id = hashlib.sha1('%s_%s' % (commit, file)).digest()
        return Object(obj_id, lines, sha1.digest(), sha256.digest(), sha512.digest(), out)

