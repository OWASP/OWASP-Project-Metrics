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
from datetime import datetime, tzinfo
from functools import partial
import hashlib
import os.path
import subprocess as subp
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

    def __init__(self, code, stderr):
        self.code = int(code)
        self.stderr = str(stderr)

    def __str__(self):
        return '<GitCmdError: [%d] %s>' \
               % (self.code, self.stderr.encode('string-escape'))


__all__ = 'Git',


BUFSIZE = 4096
EOL = '\n'


def clone(git, repo, out):
    p = subp.Popen((git, 'clone', repo, out), stdout=subp.PIPE, stderr=subp.PIPE)
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
                if not _buf:
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

Stat = namedtuple('Stat', ('commit', 'add', 'rm', 'src_file', 'dst_file'))

Blob = namedtuple('Blob', ('hash', 'mode', 'name'))

Object = namedtuple('Object', ('id', 'lines', 'sha1', 'sha256', 'sha512', 'raw'))


IN_INFO = 1
IN_DATA = 2


class Git(object):

    def __init__(self, path, git='git'):
        self.git_out = partial(git_cmd, str(git), os.path.abspath(path))
        def git_ignore_out(*args):
            for _ in self.git_out(*args):
                pass
        self.git_cmd = git_ignore_out

    @staticmethod
    def clone(path, out='./', git='git'):
        out = os.path.abspath(out)
        for line in clone(git, path, out):
            pass
        return Git(os.path.join(out, '.git'))        

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
                dt, _, tz = fields[6].rpartition(' ')
                # TODO set timezone
                fields[6] = datetime.strptime(dt, '%Y-%m-%d %H:%M:%S')
                dt, _, tz = fields[9].rpartition(' ')
                # TODO set timezone
                fields[9] = datetime.strptime(dt, '%Y-%m-%d %H:%M:%S')
                if len(fields) != 12:
                    raise GitFormatError("invalid line %r" % line)
                in_data = 1
        if fields and text:
            yield Commit(*(tuple(fields[1:-1]) + ('\n'.join(text),)))

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
                src_mode, dst_mode, src_hash, dst_hash, finfo = line.split(' ')
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
                yield commit, src, dst, add, rm

    @property
    def trees(self):
        for line in self.git_out('rev-list', '--all'):
            yield line.strip()


    def blobs(self, tree):
        if tree not in tuple(self.trees):
            raise GitError("unknown tree %r" % tree)
        for line in self.git_out('ls-tree', '-r', tree):
            fields = line.split(' ')
            mode, otype = fields[:2]
            ohash, oname = ' '.join(fields[2:]).split('\t')
            if otype == 'blob':
                yield Blob(ohash, mode, oname)

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

