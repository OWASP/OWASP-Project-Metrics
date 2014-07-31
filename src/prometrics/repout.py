from collections import Counter
from datetime import datetime
import itertools
import math
import os
import string

import sys
reload(sys)
sys.setdefaultencoding('utf-8')

from jinja2 import Environment, PackageLoader
import jinja2


class ReportError(Exception):

    def __init__(self, ex):
        Exception.__init__(self, str(ex))
        self.ex = ex


def prepare_fname(name):
    return ''.join(ch.upper() for ch in name if ch.isalnum() or ch in '_. ').replace(' ', '_').replace('.', '_')


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
    '.adb': LANG_ADA,
    '.ads': LANG_ADA,
    '.c': LANG_C,
    '.cc': LANG_C,
    '.cpp': LANG_CPP,
    '.cxx': LANG_CPP,
    '.cs': LANG_CSHARP,
    '.css': LANG_CSS,
    '.go': LANG_GO,
    '.html': LANG_HTML,
    '.htm': LANG_HTML,
    '.java': LANG_JAVA,
    '.js': LANG_JAVASCRIPT,
    '.pl': LANG_PERL,
    '.php': LANG_PHP,
    '.py': LANG_PYTHON,
    '.rb': LANG_RUBY,
    '.scala': LANG_SCALA,
    '.sh': LANG_SHELL
}


def to_html5(repo, dirpath='./', project_name=''):
    try:
        dirpath = os.path.abspath(dirpath)
        #
        env = Environment(loader=PackageLoader('prometrics', 'templates'))
        env.globals['DATE_FMT'] = '%d.%m.%Y'
        env.globals['sort_by_text_len'] = lambda it: tuple(v for v in sorted(it, key=lambda c: len(c.text), reverse=1))
        env.globals['filter'] = lambda it, val: (v for v in it if it == val)
        env.globals['filter_attr'] = lambda it, attr, val: (v for v in it if getattr(v, attr) == val)
        env.globals['EXT2LANGUAGE'] = EXT2LANGUAGE
        env.globals['prepare_fname'] = prepare_fname
        now = datetime.now()
        #
        branch = repo.branch
        branch_dir = os.path.join(dirpath, prepare_fname(branch))
        if not os.path.exists(branch_dir):
            os.mkdir(branch_dir)
        # commits
        commits = list(repo.commits())
        commits.sort(key=lambda c: c.commiter_date)
        #
        first_commit = min(commits, key=lambda c: c.author_date).author_date
        last_commit = max(commits, key=lambda c: c.author_date).author_date
        delta_commits = last_commit - first_commit
        # iterate commits
        authors = {}
        weeks_len = (delta_commits.days // 7) + 1
        weeks = [0] * weeks_len
        hours = [0] * 24
        months = [0] * 12
        month_days = [0] * 31
        week_days = [0] * 7
        week_hours = [[0] * 24 for _ in xrange(7)]
        last_7days_commits = []
        last_30days_commits = []
        last_90days_commits = []
        last_7days_stats = []
        last_30days_stats = []
        last_90days_stats = []
        last_7days_authors = set()
        last_30days_authors = set()
        last_90days_authors = set()
        inactive_days = 0
        for cm in commits:
            # authors
            auth = authors.setdefault(cm.author_email, {})
            auth.setdefault(cm.author_name, []).append(cm)
            # inactive days
            delta = cm.author_date - first_commit
            inactive_days += delta.days
            # activity
            hours[cm.author_date.hour] += 1
            weeks[delta.days // 7] += 1
            months[cm.author_date.month-1] += 1
            month_days[cm.author_date.day-1] += 1
            week_days[cm.author_date.weekday()] += 1
            week_hours[cm.author_date.weekday()][cm.author_date.hour] += 1
            if delta.days <= 7:
                last_7days_commits.append(cm)
                last_7days_authors.add(cm.author_email)
            if delta.days <= 30:
                last_30days_commits.append(cm)
                last_30days_authors.add(cm.author_email)
            if delta.days <= 90:
                last_90days_commits.append(cm)
                last_90days_authors.add(cm.author_email)
        inactive_days += (now - commits[-1].author_date).days
        #
        hash2commit = {cm.hash: cm for cm in commits}
        #
        stats = {}
        for st in repo.stats():
            stats.setdefault(st.commit, []).append(st)
            delta = hash2commit[st.commit].author_date - first_commit
            if delta.days <= 7:
                last_7days_stats.append(st)
            if delta.days <= 30:
                last_30days_stats.append(st)
            if delta.days <= 90:
                last_90days_stats.append(st)
        #
        changes = {}
        for ch in repo.changes():
            changes.setdefault(ch.commit, []).append(ch)
        #
        for email, names in authors.iteritems():
            _, name = max((len(commits), name) for name, commits in names.iteritems())
            authors[email] = sum(len(v) for v in names.values()), name, list(itertools.chain(*names.itervalues()))
        #
        files = list(repo.files())
        extensions = Counter(os.path.splitext(f.name)[1] for f in files)
        #
        commits_per_day = {}
        for cm in commits:
            date = cm.author_date
            commits_per_day.setdefault((date.year, date.month, date.day), {}).setdefault(cm.author_email, []).append(cm)
        commits_per_day = [(len(cms), auth_email, datetime(*date))
                           for date, auths in commits_per_day.iteritems()
                           for auth_email, cms in auths.iteritems()]
        #
        tot_add=sum(st.add for st in repo.stats())
        tot_rm=sum(st.rm for st in repo.stats())
        # summary.html
        template = env.get_template('summary.html')
        with open(os.path.join(branch_dir, 'index.html'), 'wb') as fout:
            for chunk in template.generate(
                                       now=now,
                                       project=project_name,
                                       branch=repo.branch,
                                       commits=commits,
                                       files=files,
                                       extensions=extensions,
                                       lines=tot_add-tot_rm,
                                       end_interval=last_commit,
                                       inactive_days=inactive_days,
                                       project_name='',
                                       authors=authors,
                                       start_interval=first_commit,
                                       last_7days_commits=last_7days_commits,
                                       last_30days_commits=last_30days_commits,
                                       last_90days_commits=last_90days_commits,
                                       last_7days_authors=last_7days_authors,
                                       last_30days_authors=last_30days_authors,
                                       last_90days_authors=last_90days_authors):
                fout.write(chunk)
        # contributors.html
        template = env.get_template('authors.html')
        with open(os.path.join(branch_dir, 'authors.html'), 'wb') as fout:
            for chunk in template.generate(
                                project=project_name,
                                authors=authors,
                                commits=commits,
                                commits_per_day=commits_per_day):
                fout.write(chunk)
        # activity.html
        template = env.get_template('activity.html')
        with open(os.path.join(branch_dir, 'activity.html'), 'wb') as fout:
            for chunk in template.generate(
                                        project=project_name,
                                        commits=commits,
                                        hours=hours,
                                        weeks=weeks,
                                        months=months,
                                        month_days=month_days,
                                        week_days=week_days,
                                        week_hours=week_hours):
                fout.write(chunk)
        # code.html
        template = env.get_template('code.html')
        with open(os.path.join(branch_dir, 'code.html'), 'wb') as fout:
            for chunk in template.generate(
                            project=project_name,
                            commits=commits,
                            files=files,
                            last_7days_stats=last_7days_stats,
                            last_30days_stats=last_30days_stats,
                            last_90days_stats=last_90days_stats,
                            stats=stats,
                            changes=changes,
                            hash2commit=hash2commit,
                            tot_add=tot_add,
                            tot_rm=tot_rm,
                            exts=extensions):
                fout.write(chunk)
    except jinja2.TemplateError, ex:
        raise ReportError(ex)
        

def html5_index(dirpath, repositories):
    dirpath = os.path.abspath(dirpath)
    #
    env = Environment(loader=PackageLoader('prometrics', 'templates'))
    env.globals['prepare_fname'] = prepare_fname
    template = env.get_template('index.html')
    with open(os.path.join(dirpath, 'index.html'), 'wb') as fout:
        for chunk in template.generate(
                                pathjoin=os.path.join,
                                repositories=repositories):
            fout.write(chunk)

