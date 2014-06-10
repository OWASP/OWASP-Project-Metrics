#!/usr/bin/python2.7 -OOBRtt
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
"""Tool to measure project activity and quality"""
from collections import defaultdict
from datetime import datetime, timedelta
import functools
import hashlib
import heapq
import json
import os
import subprocess as subp
import sys

from docopt import docopt
from jinja2 import Environment, PackageLoader
from namedlist import namedlist


__doc__ = """Tool to measure project activity and quality.

Usage: prometrics [--branches=<BRANCHES>]  [--output-format=<FMT>] [--path=<PATH>] [--project-name=<PROJ>] OUTPUT

Options:
    -b --branches=<BRANCHES>    branches to consider
    -f --output-format=<FMT>    output-format [default: json]
    -p --path=<PATH>            repository path [default: ./]
    -n --project-name=<PROJ>    project name

"""


# status codes
STATUS_ADD = 'A'
STATUS_COPY = 'C'
STATUS_DELETE = 'D'
STATUS_MODIFICATION = 'M'
STATUS_RENAME = 'R'
STATUS_CHANGE_TYPE = 'T'
STATUS_UNMERGED = 'U'
STATUS_UNKNOWN = 'X'


Commit = namedlist('Commit',
                    ('hash', 'tree_hash', 'parent_hash', 'author_name',
                     'author_email', 'author_date', 'commiter_name',
                     'commiter_email', 'commiter_date', 'subject',
                     'author_tz', 'commiter_tz', 'text', 'body'))

File = namedlist('File',
                  ('commit', 'op', 'src_mode', 'src_hash', 'src_file', 'dst_mode',
                  'dst_hash', 'dst_file', 'similarity', 'changes', 'add', 'rm',
                  'diff_ranges', 'trees', 'src_id', 'dst_id'))

Change = namedlist('Change',
                    ('commit_hash', 'src_mode', 'dst_mode', 'src_hash',
                    'dst_hash', 'status', 'score', 'src_file', 'dst_file'))

Blob = namedlist('Blob', ('hash', 'mode', 'file'))


Object = namedlist('Object',
                   ('id', 'sha1', 'sha256', 'sha512', 'mime', 'encoding',
                   'size', 'lines'))


# consts
BUFSIZE = 4096
CR = '\r'
LF = '\n'
CRLF = '\r\n'

NULL_HASH = '0000000000000000000000000000000000000000'

NOW = datetime.now()

# errors
ERR_REPOISNOTDIR = 1
ERR_NOTGITREPO = 2
ERR_UNKNOWNBRANCH = 3
ERR_UNKNOWNFORMAT = 4


class GitError(Exception):

    def __init__(self, code, stdout, stderr):
        self.code = int(code)
        self.stdout = str(stdout)
        self.stderr = str(stderr)

    def __str__(self):
        return """GITERROR: [%d]
STDOUT:
%r

STDERR:
%r
""" % (self.code, self.stdout, self.stderr)


GIT_CMD = 'git'

def rm_prefix(string, prefix):
    return string[len(prefix):] if string.startswith(prefix) else string


def git_rename_limit(path, limit):
    p = subp.Popen((GIT_CMD, '--git-dir=%s' % path, 'config', 'merge.renameLimit', str(int(limit))), stdout=subp.PIPE, stderr=subp.PIPE)
    stdout, stderr = p.communicate()
    code = p.returncode
    if code:
        raise GitError(code, stdout, stderr)


def get_all_branches(path):
    """Get all branches of a repository"""
    p = subp.Popen((GIT_CMD, '--git-dir=%s' % path, 'branch', '--no-color', '--list', '--no-abbrev'), stdout=subp.PIPE, stderr=subp.PIPE)
    stdout, stderr = p.communicate()
    code = p.returncode
    if code:
        raise GitError(code, stdout, stderr)
    actual = None
    branches = []
    for line in stdout.split('\n'):
        line = line.strip()
        if not line:
            continue
        if line.startswith('*'):
            branch = line.partition(' ')[2].strip()
            branches.insert(0, branch)
        else:
            branch = line.strip()
            branches.append(branch)
    return branches


def ls_files(path):
    p = subp.Popen((GIT_CMD, '--git-dir=%s' % path, 'ls-files', '--full-name',
                    '-t', '--stage'), stdout=subp.PIPE, stderr=subp.PIPE)
    stdout, stderr = p.communicate()
    code = p.returncode
    if code:
        raise GitError(code, stdout, stderr)
    lines = stdout.split('\n')
    for line in lines:
        yield line.split(' ')[-1]


def move_to_branch(path, branch):
    p = subp.Popen((GIT_CMD, '--git-dir=%s' % path, 'checkout', branch), stdout=subp.PIPE, stderr=subp.PIPE)
    stdout, stderr = p.communicate()
    code = p.returncode
    if code:
        raise GitError(code, stdout, stderr)


COM_ST_START = 1
COM_ST_NEXT_FIELD = 2
COM_ST_IN_TEXT = 3


def get_commit_body(path, commit_hash):
    p = subp.Popen((GIT_CMD, '--git-dir=%s' % path, 'log', '-n 1', '--format=%B', commit_hash),
                   stdout=subp.PIPE, stderr=subp.PIPE)
    stdout, stderr = p.communicate()
    code = p.returncode
    if code:
        raise GitError(code, stdout, stderr)
    return stdout


def get_all_commits(path):
    p = subp.Popen((GIT_CMD, '--git-dir=%s' % path, 'log', '-B', '-M20', '-C',
                    '-l9999', '--find-copies-harder',
                    '--pretty=format:{%n/C01/%H%n/C02/%T%n/C03/%P%n/C04/%an%n/C05/%ae%n/C06/%ai%n/C07/%cn%n/C08/%ce%n/C09/%ci%n/C10/%s%n/C11/%n/C12/%n/C13/%n'
                    '--pickaxe-all', '--summary'),
                   stdout=subp.PIPE, stderr=subp.PIPE)
    stdout, stderr = p.communicate()
    code = p.returncode
    if code:
        raise GitError(code, stdout, stderr)
    state = COM_ST_START
    fno = 0
    fields = []
    text = []
    for line in stdout.split('\n'):
        line = line.strip()
        if state == COM_ST_START:
            if line == '{':
                state = COM_ST_NEXT_FIELD
                fno = 1
            elif not fields:
                continue
            elif not line:
                continue
        elif state == COM_ST_NEXT_FIELD:
            if fno == 13:
                state = COM_ST_IN_TEXT
                fno = 0
            else:
                fields.append(rm_prefix(line, '/C%s/' % str(fno).zfill(2)))
                fno += 1
        elif state == COM_ST_IN_TEXT:
            if line == '{':
                fields.append('\n'.join(text))
                fields.append(get_commit_body(path, fields[0]))
                # changes
                yield Commit(*fields)
                fields = []
                text = []
                state = COM_ST_NEXT_FIELD
                fno = 1
            else:
                text.append(line)
        else:
            raise Exception
    if fields:
        fields.append(text)
        fields.append(get_commit_body(path, fields[0]))
        yield Commit(*fields)


def short2long_hash(path, short):
    if short == '0000000':
        return '0' * 40
    p = subp.Popen((GIT_CMD, '--git-dir=%s' % path, 'rev-parse', '--verify', short),
                   stdout=subp.PIPE, stderr=subp.PIPE)
    stdout, stderr = p.communicate()
    code = p.returncode
    if code:
        raise GitError(code, stdout, stderr)
    return stdout.strip()
    


CH_ST_START = 1
CH_ST_COMMIT = 2
CH_ST_NEXT_CHANGE = 3

def get_all_changes(path):
    p = subp.Popen((GIT_CMD, '--git-dir=%s' % path, 'whatchanged', '-B', '-M20',
                    '-C', '-l9999', '--find-copies-harder', '--pickaxe-all',
                    '-r', '--pretty=format:{%n/C01/%H%n/W12/'),
                   stdout=subp.PIPE, stderr=subp.PIPE)
    stdout, stderr = p.communicate()
    code = p.returncode
    if code:
        raise GitError(code, stdout, stderr)
    state = CH_ST_START
    commit_hash = src_mode = dst_mode = hash_src  = status = score = src_file = dst_file= None
    hash_dst = status = score = src_file = dst_file = None
    for line in stdout.split('\n'):
        line = line.strip()
        if state == CH_ST_START:
            if line == '{':
                state = CH_ST_COMMIT
                commit = None
            else:
                continue
        elif state == CH_ST_COMMIT:
            if line.startswith('/C01/'):
                commit_hash = rm_prefix(line, '/C01/').strip()
            else:
                raise Exception
            state = CH_ST_NEXT_CHANGE
        elif state == CH_ST_NEXT_CHANGE:
            # TODO only one time
            if line == '/W12/':
                continue
            elif not line:
                state = CH_ST_START
                src_mode = dst_mode = hash_src = None
                hash_dst = status = score = src_file = dst_file = None
            else:
                fields = line.split(' ')
                op = ' '.join(fields[4:])
                src_mode, dst_mode, hash_src, hash_dst = fields[:4]
                src_mode = rm_prefix(src_mode, ':')
                hash_src = short2long_hash(path, hash_src.rstrip('.'))
                hash_dst = short2long_hash(path, hash_dst.rstrip('.'))
                status = op[0]
                if status in (STATUS_ADD, STATUS_DELETE,
                              STATUS_CHANGE_TYPE, STATUS_UNMERGED,
                              STATUS_UNKNOWN):
                    dst_file = src_file = op[2:]
                    score = None
                elif status == STATUS_MODIFICATION:
                    score, src_file = op[1:].split('\t')
                    score = int(score) if score else None
                    dst_file = src_file
                elif status in (STATUS_RENAME, STATUS_COPY,):
                    score, src_file, dst_file = op[1:].split('\t')
                    score = int(score)
                else:
                    raise Exception
                
                yield Change(commit_hash, src_mode, dst_mode, hash_src,
                             hash_dst, status, score, src_file, dst_file)
                src_mode = dst_mode = hash_src =  None
                hash_dst = status = score = src_file = dst_file = None
        else:
            raise Exception


STAT_ST_START = 1
STAT_ST_COMMIT = 2
STAT_ST_NEXT_STAT = 3


Stat = namedlist('Stat', ('commit', 'add', 'rm', 'src_file', 'dst_file'))

def get_all_stats(path):
    p = subp.Popen((GIT_CMD, '--git-dir=%s' % path, 'log', '--numstat', '-B', '-M20',
                    '-C', '-l9999', '--find-copies-harder', '--pickaxe-all',
                    '-r', '--pretty=format:{%n/C01/%H%n/P12/'),
                   stdout=subp.PIPE, stderr=subp.PIPE)
    stdout, stderr = p.communicate()
    code = p.returncode
    if code:
        raise GitError(code, stdout, stderr)
    state = STAT_ST_START
    for line in stdout.split('\n'):
        line = line.strip()
        if state == STAT_ST_START:
            if line == '{':
                state = STAT_ST_COMMIT
            else:
                continue
        elif state == STAT_ST_COMMIT:
            if line.startswith('/C01/'):
                commit_hash = rm_prefix(line, '/C01/').strip()
            else:
                raise Exception
            state = STAT_ST_NEXT_STAT
        elif state == STAT_ST_NEXT_STAT:
            # TODO only one time
            if line == '/P12/':
                continue
            elif not line or line == '{':
                state = STAT_ST_START
                commit_hash = add = rm = fname = None
            else:
                add, rm, fname = line.split('\t')
                start = fname.find('{')
                end = fname.find('}')
                if start < end:
                    prefix = fname[:start]
                    middle = fname[start+1:end]
                    postfix = fname[end+1:]
                    src_middle, sep, dst_middle = middle.partition(' => ')
                    if sep:
                        src_file = '%s%s%s' % (prefix, src_middle, postfix)
                        dst_file = '%s%s%s' % (prefix, dst_middle, postfix)
                else:
                    src_file, sep, dst_file = fname.partition(' => ')
                    if not sep:
                        src_file = dst_file = fname
                yield Stat(commit_hash, int(add) if add.isdigit() else 0, int(rm) if rm.isdigit() else 0, src_file.replace('//', '/'), dst_file.replace('//', '/'))
                add = rm = src_file = dst_file = None


def get_tree_commits(path):
    p = subp.Popen((GIT_CMD, '--git-dir=%s' % path, 'log', '--reverse',
                    "--pretty=format:%T %H"),
                   stdout=subp.PIPE, stderr=subp.PIPE)
    stdout, stderr = p.communicate()
    code = p.returncode
    if code:
        raise GitError(code, stdout, stderr)
    for line in stdout.split('\n'):
        tree_hash, commit_hash = line.split(' ')
        yield tree_hash, commit_hash


def get_trees(path):
    p = subp.Popen((GIT_CMD, '--git-dir=%s' % path, 'rev-list', '--all'),
                   stdout=subp.PIPE, stderr=subp.PIPE)
    stdout, stderr = p.communicate()
    code = p.returncode
    if code:
        raise GitError(code, stdout, stderr)
    for line in stdout.split('\n'):
        line = line.strip()
        if line:
            yield line


def get_blobs_by_tree(path, tree):
    p = subp.Popen((GIT_CMD, '--git-dir=%s' % path, 'ls-tree', '-r', tree),
                   stdout=subp.PIPE, stderr=subp.PIPE)
    stdout, stderr = p.communicate()
    code = p.returncode
    if code:
        raise GitError(code, stdout, stderr)
    for line in stdout.split('\n'):
        line = line.strip()
        if not line:
            continue
        fields = line.split(' ')
        mode, otype = fields[:2]
        ohash, oname = ' '.join(fields[2:]).split('\t')
        if otype == 'blob':
            yield Blob(ohash, mode, oname)


def get_changes_by_commit(path, commit):
    p = subp.Popen((GIT_CMD, '--git-dir=%s' % path, 'diff-tree', '-r', commit),
                   stdout=subp.PIPE, stderr=subp.PIPE)
    stdout, stderr = p.communicate()
    code = p.returncode
    if code:
        raise GitError(code, stdout, stderr)
    for line in stdout.split('\n')[1:]:
        line = line.strip()
        if not line:
            continue
        fields = line.split(' ')
        op = ' '.join(fields[4:])
        src_mode, dst_mode, hash_src, hash_dst = fields[:4]
        src_mode = rm_prefix(src_mode, ':')
        hash_src = short2long_hash(path, hash_src.rstrip('.'))
        hash_dst = short2long_hash(path, hash_dst.rstrip('.'))
        status = op[0]
        if status in (STATUS_ADD, STATUS_MODIFICATION, STATUS_DELETE,
                      STATUS_CHANGE_TYPE, STATUS_UNMERGED,
                      STATUS_UNKNOWN):
            src_file = op[2:]
            score = dst_file = None
        elif status in (STATUS_RENAME, STATUS_COPY):
            score, src_file, dst_file = op[1:].split('\t')
            score = int(score)
        else:
            raise Exception
        yield Change(commit, src_mode, dst_mode, hash_src, hash_dst,
                     status, score, src_file, dst_file)
        
def get_diff_stat(path, blob1, blob2):
    p = subp.Popen((GIT_CMD, '--git-dir=%s' % path, 'diff', '--numstat', blob1, blob2),
                   stdout=subp.PIPE, stderr=subp.PIPE)
    stdout, stderr = p.communicate()
    code = p.returncode
    if code:
        raise GitError(code, stdout, stderr)
    add, rm = stdout.strip().split('\t')
    return int(add), int(rm)


def get_diff(path, blob1, blob2):
    p = subp.Popen((GIT_CMD, '--git-dir=%s' % path, 'diff', blob1, blob2),
                   stdout=subp.PIPE, stderr=subp.PIPE)
    stdout, stderr = p.communicate()
    code = p.returncode
    if code:
        raise GitError(code, stdout, stderr)
    if not stdout.strip():
         # ??? or None
        return ''
    lines = stdout.split('\n')
    if len(lines) < 5:
        return ''
    line = lines[4].lstrip(' @')
    return line[:line.index('@')].strip()


def get_all_blobs(path):
    blobs = set()
    for tree in get_trees(path):
        for blob in get_blobs_by_tree(path, tree):
            if (blob.hash, blob.file) not in blobs:
                yield blob
                blobs.add((blob.hash, blob.file))


def get_obj(path, commit_hash, dst_file):
    p = subp.Popen((GIT_CMD, '--git-dir=%s' % path, 'show', '%s:%s' % (commit_hash, dst_file)),
                   stdout=subp.PIPE, stderr=subp.PIPE)
    stdout, stderr = p.communicate()
    code = p.returncode
    if code:
        raise GitError(code, stdout, stderr)
    objid = hashlib.sha1('%s_%s' % (commit_hash, dst_file)).digest()
    sha1 = hashlib.sha1(stdout).digest()
    sha256 = hashlib.sha256(stdout).digest()
    sha512 = hashlib.sha512(stdout).digest()
    crlf = stdout.count(CRLF)
    cr = stdout.count(CR)
    lf = stdout.count(LF)
    cr = crlf - cr 
    lf = crlf - lf
    lines = crlf + cr + lf
    size = len(stdout)
    return Object(objid, sha1, sha256, sha512, None, None, size, lines)


def get_all_info(path):
    files = []
    commits = defaultdict(dict)
    print "Searching all changes..."
    for change in get_all_changes(path):
        f = File(change.commit_hash, change.status,
                 change.src_mode, change.src_hash, change.src_file,
                 change.dst_mode, change.dst_hash, change.dst_file,
                 None, None, None, None, None, None, None, None)
        commits[f.commit][f.src_file] = f
        files.append(f) # ??? is this useful?
    print "Searching all stats..."
    for stat in get_all_stats(path):
        f = commits[stat.commit][stat.src_file]
        f.changes = stat.add + stat.rm
        f.add = stat.add
        f.rm = stat.rm
    print "Searching all commits for each tree..."
    for tree, commit in get_tree_commits(path):
        for f in commits[commit].itervalues():
            f.trees = [tree]
    # check blobs
    print "Searching all blobs..."
    blobs = get_all_blobs(path)
    blobs_hashes = {b.hash for b in blobs}
    print "Verifing blobs..."
    for commit in get_all_commits(path):
        for change in get_changes_by_commit(path, commit.hash):
            if change.src_hash != NULL_HASH and change.src_hash not in blobs_hashes:
                raise Exception
            if change.dst_hash != NULL_HASH and change.dst_hash not in blobs_hashes:
                raise Exception
    # ??? is it redundant?
    # for f in files:
    #    add, rm = get_diff_stat(f.src_hash, f.dst_hash)
    print "Searching all objects..."
    objs = []
    for f in files:
        f.diff_ranges = get_diff(path, f.src_hash, f.dst_hash) \
                        if f.src_hash != NULL_HASH and f.dst_hash != NULL_HASH and f.src_hash != f.dst_hash \
                        else ''
        if f.dst_hash != NULL_HASH:
            objs.append(get_obj(path, f.commit, f.dst_file))
    print "Searching all commits..."
    commits = [commit for commit in get_all_commits(path)]
    return commits, files, blobs, objs


def get_actual_files(path):
    p = subp.Popen((GIT_CMD, '--git-dir=%s' % path, 'ls-files', '--full-name', '-t', '--stage'),
                   stdout=subp.PIPE, stderr=subp.PIPE)
    stdout, stderr = p.communicate()
    code = p.returncode
    if code:
        raise GitError(code, stdout, stderr)
    for line in stdout.split('\n'):
        line = line.strip()
        yield line.split('\t')[-1].strip()


LANG_ADA = 'ada'
LANG_C = 'c'
LANG_CPP = 'c++'
LANG_CSHARP = 'c#'
LANG_CSS = 'css'
LANG_GO = 'go'
LANG_HTML = 'html'
LANG_JAVA = 'java'
LANG_JAVASCRIPT = 'javascript'
LANG_PERL = 'perl'
LANG_PHP = 'php'
LANG_PYTHON = 'python'
LANG_RUBY = 'ruby'
LANG_SCALA = 'scala'
LANG_SHELL = 'shell'


EXT2LANGUAGE = {
    'adb': LANG_ADA,
    'ads': LANG_ADA,
    'c': LANG_C,
    'cc': LANG_C,
    'cpp': LANG_CPP,
    'cxx': LANG_CPP,
    'cs': LANG_CSHARP,
    'css': LANG_CSS,
    'go': LANG_GO,
    'html': LANG_HTML,
    'htm': LANG_HTML,
    'java': LANG_JAVA,
    'js': LANG_JAVASCRIPT,
    'pl': LANG_PERL,
    'php': LANG_PHP,
    'py': LANG_PYTHON,
    'rb': LANG_RUBY,
    'scala': LANG_SCALA,
    'sh': LANG_SHELL
}


# indexes for json output
INDEX_PROJ_NAME = 'proj_name'
INDEX_REPO_NAME = 'repo_name'
INDEX_BRANCHES = 'branches'
INDEX_COMMITS = 'commits'
INDEX_FILES = 'files'

INDEX_COMMIT_CHANGED_FILES = 'changed_files'
INDEX_COMMIT_CONTENT_ATTRIBUTION = 'content_attribution'
INDEX_COMMIT_AUTHOR_TRACK = 'author_track'
INDEX_COMMIT_ACTION_ATTRIBUTION = 'action_attribution'

INDEX_FILE_SIZE = 'size'
INDEX_FILE_MAGIC_TYPE = 'magic'
INDEX_FILE_CR_COUNT = 'cr'
INDEX_FILE_LF_COUNT = 'lf'
INDEX_FILE_CRLF_COUNT = 'crlf'
INDEX_FILE_LINES_COUNT = 'lines'
INDEX_FILE_MD5 = 'md5'
INDEX_FILE_SHA1 = 'sha1'
INDEX_FILE_SHA256 = 'sha256'
INDEX_FILE_SHA512 = 'sha512'
INDEX_FILE_SDEEP = 'sdeep'

INDEX_STATS_FILES_ADD = 'files_add'
INDEX_STATS_FILES_CHANGED = 'files_changed'
INDEX_STATS_FILES_UNCHANGED = 'files_unchanged'
INDEX_STATS_FILES_DELETED = 'files_deleted'


namedlist2dict = lambda nl: dict(nl._asdict())


def info2json(Out, proj_name, repo_name, branches_info, actual_files):
    import json
    branches = {}
    for branch_name, info in branches_info.iteritems():
        branch_info = branches[branch_name] = {}
        commits, files, blobs, objs = info
        branch_info[INDEX_COMMITS] = {commit.hash: namedlist2dict(commit) for commit in commits}
    with open(out, 'wb') as fout:
        fout.write(json.dumps({
            INDEX_PROJ_NAME: proj_name,
            INDEX_REPO_NAME: repo_name,
            INDEX_BRANCHES: branches
        }, sort_keys=1, indent=4))
    

# html
class Placeholder(object):
    pass


env = Environment(loader=PackageLoader('prometrics', 'templates'))


def strftime(value, fmt):
    return value.strftime(fmt)


env.filters['strftime'] = strftime

env.globals['NOW'] = NOW


def commits_last_interval(days):
    def _commits_per_interval(commits):
        count = 0
        for cm in commits:
            if (NOW - cm.commiter_date).total_seconds() // (60 * 60 * 24) <= days:
                count += 1
        return count
    return _commits_per_interval

env.filters['commits_last_week'] = commits_last_interval(7)
env.filters['commits_last_month'] = commits_last_interval(30)
env.filters['commits_last_3months'] = commits_last_interval(30 * 3)
env.filters['commits_last_6months'] = commits_last_interval(30 * 6)


def commiters_last_interval(days):
    def _commits_per_interval(commits):
        commiters = set()
        for cm in commits:
            if (NOW - cm.commiter_date).total_seconds() // (60 * 60 * 24) <= days:
                commiters.add(cm.commiter_email)
        return len(commiters)
    return _commits_per_interval

env.filters['commiters_last_week'] = commiters_last_interval(7)
env.filters['commiters_last_month'] = commiters_last_interval(30)
env.filters['commiters_last_3months'] = commiters_last_interval(30 * 3)
env.filters['commiters_last_6months'] = commiters_last_interval(30 * 6)


def top_commiters(n):
    def _top_commiters(commiters):
        top = [None] * n
        tail = n - 1
        for email, counts in commiters.iteritems():
            tot = 0
            max_count = None
            for name, count in counts.iteritems():
                tot += count
                max_count = max(None, (count, name))
            heapq.heappushpop(top, (tot, max_count[1]))
        return heapq.nlargest(n, top)
    return _top_commiters

env.filters['top_5commiters'] = top_commiters(5)
env.filters['top_10commiters'] = top_commiters(10)


def commits_longest_text(n):
    def _commits_longest_text(commits):
        return heapq.nlargest(n, commits, lambda c: len(c.body))
    return _commits_longest_text

env.filters['commits_longest_10text'] = commits_longest_text(10)


OpStats = namedlist('OpStats', ('total', 'week', 'month', 'months3', 'months6'))
def ops_in_interval(op, commits, files):
    stats = OpStats(0, 0, 0, 0, 0)
  
    for f in files:
        commit = commits[f.commit]
        delta = (NOW - commit.commiter_date).total_seconds() // (60 * 60 * 24)
        if f.op == op:
            stats.total += 1
            if delta < 7:
                stats.week += 1
            elif delta <= 30:
                stats.week += 1
                stats.month += 1
            elif delta <= 90:
                stats.week += 1
                stats.month += 1
                stats.months3 += 1  
            elif delta < 180:
                stats.week += 1
                stats.month += 1
                stats.months3 += 1
                stats.months6 += 1
    return stats


def info2html5(out, proj_name, repo_name, branches_info, actual_files):
    branches = {}
    for branch_name, info in branches_info.iteritems():
        branch_info = branches[branch_name] = Placeholder()
        commits, files, blobs, objs = info
        branch_info.commits = commits
        branch_info.files = files
        branch_info.blobs = blobs
        branch_info.objs = objs
        for cm in commits:
            cm.author_date = datetime.strptime(cm.author_date[:-6], '%Y-%m-%d %H:%M:%S')
            cm.commiter_date = datetime.strptime(cm.commiter_date[:-6], '%Y-%m-%d %H:%M:%S')
        commits.sort(key=lambda c: c.commiter_date)
        branch_info.commiters = defaultdict(lambda: defaultdict(int))
        for cm in commits:
            email = branch_info.commiters.setdefault(cm.commiter_email, {})
            count = email.setdefault(cm.commiter_name, 0)
            email[cm.commiter_name] = count + 1
    #
    master_commits = branches['master'].commits
    master_files = branches['master'].files
    #
    inactive_days = 0
    last_commit = master_commits[0].commiter_date
    for commit in master_commits:
        delta = (commit.commiter_date - last_commit).total_seconds() // (60 * 60 * 24)
        if delta > 1:
            inactive_days += int(delta)
            last_commit += timedelta(int(delta))
        elif delta == 1:
            last_commit += timedelta(1)
    inactive_days += (NOW - last_commit).total_seconds() // (60 * 60 * 24)
    weekly_commits = []
    week_start = master_commits[0].commiter_date
    commits_count = 0
    for commit in master_commits:
        delta = int((commit.commiter_date - week_start).total_seconds() // (60 * 60 * 24))
        if delta < 7:
            commits_count += 1
        else:
            for _ in xrange(delta // 7):
                weekly_commits.append(0)
            weekly_commits.append(commits_count)
            commits_count = 1
            week_start += timedelta(7)
    weekly_commits.append(commits_count)
    #
    hourly_commits = [0] * 24
    for commit in master_commits:
        hourly_commits[commit.commiter_date.hour] += 1
    #
    weekday_commits = [0] * 7
    for commit in master_commits:
        weekday_commits[commit.commiter_date.weekday()] += 1
    #
    hour_week_commits = [[0] * 24 for _ in xrange(7)]
    for commit in master_commits:
        hour_week_commits[commit.commiter_date.weekday()][commit.commiter_date.hour] += 1
    #
    languages = defaultdict(int)
    for f in actual_files:
        lang = EXT2LANGUAGE.get(os.path.splitext(f)[1][1:], None)
        if lang:
            languages[lang] += 1
    #
    Author = namedlist('Author', ('email', 'name', 'commits', 'add', 'rm', 'first', 'last'))
    _authors = defaultdict(dict)
    for commit in master_commits:
        count = _authors[commit.author_email].setdefault(commit.author_name, 0)
        _authors[commit.author_email][commit.author_name] += 1
    authors = {}
    for author_email, counts in _authors.iteritems():
        max_count = None
        tot = 0
        for item in counts.iteritems():
            max_count = max(max_count, item)
            tot += item[1]
        authors[author_email] = Author(author_email, max_count[0], tot, 0, 0, datetime.max, datetime.min)
    #
    commits = {cm.hash: cm for cm in commits}
    for f in master_files:
        commit = commits[f.commit]
        author = authors[commit.author_email]
        author.add += f.add or 0
        author.rm += f.rm or 0
        author.first = min(commit.commiter_date, author.first)
        author.last = max(commit.commiter_date, author.last)
    authors = sorted(authors.itervalues(), key=lambda a: a.commits, reverse=1)
    # write pages
    base = os.path.abspath(out)
    # index
    template = env.get_template('summary.html')
    with open(os.path.join(base, 'index.html'), 'wb') as fout:
        fout.write(template.render(
                   branches=branches,
                   inactive_days=inactive_days,
                   master=branches['master'],
                   project_name=proj_name,
                   repository_name=repo_name,
                   languages=languages))
    # activity
    template = env.get_template('activity.html')
    with open(os.path.join(base, 'activity.html'), 'wb') as fout:
        fout.write(template.render(
                    project_name=proj_name,
                    weekly_commits=weekly_commits,
                    hourly_commits=hourly_commits,
                    weekday_commits=weekday_commits,
                    hour_week_commits=hour_week_commits
                   ))
    # authors
    template = env.get_template('authors.html')
    with open(os.path.join(base, 'authors.html'), 'wb') as fout:
        fout.write(template.render(
                    commits=master_commits,
                    project_name=proj_name,
                    authors=authors
                   ))
    # files
    template = env.get_template('files.html')
    SatusCounter = namedlist('SatusCounter', ('add', 'rm', 'mod', 'rename', 'copy', 'change'))
    commit2stats = defaultdict(lambda: SatusCounter(0, 0, 0, 0, 0, 0))
    for f in files:
        stats = commit2stats[f.commit]
        if f.op == STATUS_ADD:
            stats.add += 1
        elif f.op == STATUS_DELETE:
            stats.rm += 1
        elif f.op == STATUS_RENAME:
            stats.rename += 1
        elif f.op == STATUS_MODIFICATION:
            stats.mod += 1
        elif f.op == STATUS_COPY:
            stats.copy += 1
        elif f.op == STATUS_CHANGE_TYPE:
            stats.change += 1
        else:
            print f
    with open(os.path.join(base, 'files.html'), 'wb') as fout:
        fout.write(template.render(
                    add_stats=ops_in_interval(STATUS_ADD, commits, files),
                    del_stats=ops_in_interval(STATUS_DELETE, commits, files),
                    mod_stats=ops_in_interval(STATUS_MODIFICATION, commits, files),
                    project_name=proj_name,
                    files=files,
                    commits=master_commits,
                    c2s=commit2stats
                   ))


OUTPUT_MAKERS = {
    'json': info2json,
    'html5': info2html5
}



def _main():
    # parse args
    opts = docopt(__doc__)
    # get repository path
    repo_path = os.path.abspath(opts['--path'])
    if os.path.split(repo_path)[1] != '.git':
        repo_path = os.path.join(repo_path, '.git')
    if not os.path.exists(repo_path):
        return ERR_NOTGITREPO
    elif not os.path.isdir(repo_path):
        return ERR_REPOISNOTDIR
    # get name
    repo_name = os.path.split(os.path.split(repo_path)[0])[1]
    proj_name = opts['--project-name'] or repo_name
    # output
    make_output = OUTPUT_MAKERS.get(opts['--output-format'], None)
    if make_output is None:
        return ERR_UNKNOWNFORMAT
    # get all branches
    # _branches = get_all_branches(repo_path)
    # selected_branches = opts['--branches']
    # if selected_branches:
    #     selected_branches = tuple(b.strip() for b in selected_branches.split(','))
    #     for b in selected_branches:
    #         if b not in _branches:
    #             return ERR_UNKNOWNBRANCH
    #     branches = selected_branches
    # else:
    #     branches = _branches
    #     del _branches
    #
    branches = {b:None for b in get_all_branches(repo_path)}
    for branch in branches:
        print "[%s]" % branch
        move_to_branch(repo_path, branch)
        branches[branch] = get_all_info(repo_path)
    if 'master' in branches:
        move_to_branch(repo_path, 'master')
    # output
    print "Printing output..."
    make_output(opts['OUTPUT'], proj_name, repo_name, branches, get_actual_files(repo_path))


if __name__ == '__main__':
    try:
        err = _main()
        if err:
            print "Error: %d" % err
    except GitError, ex:
        raise

