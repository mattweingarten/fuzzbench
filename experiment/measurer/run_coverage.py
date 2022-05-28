# Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Module for running a clang source-based coverage instrumented binary
on a corpus."""

import os
import shutil
import tempfile
from typing import List

from common import experiment_utils
from common import logs
from common import new_process
from common import sanitizer
import os
from os import listdir
from os.path import isfile, join

logger = logs.Logger('run_coverage')


# Time buffer for libfuzzer merge to gracefully exit.
EXIT_BUFFER = 15

# Memory limit for libfuzzer merge.
RSS_LIMIT_MB = 2048

# Per-unit processing timeout for libfuzzer merge.
UNIT_TIMEOUT = 10

# Max time to spend on libfuzzer merge.
MAX_TOTAL_TIME = experiment_utils.get_snapshot_seconds()


def find_crashing_units(artifacts_dir: str) -> List[str]:
    """Returns the crashing unit in coverage_binary_output."""
    return [
        # This assumes the artifacts are named {crash,oom,timeout,*}-$SHA1_HASH
        # and that input units are also named with their hash.
        filename.split('-')[1]
        for filename in os.listdir(artifacts_dir)
        if os.path.isfile(os.path.join(artifacts_dir, filename))
    ]


def list_files(dir):
    files = [join(dir, f) for f in listdir(dir) if isfile(join(dir, f))]
    return files

def get_coverage_sancov(coverage_binary, new_units_dir):
    """ XXX:Bean, invoke sancov, extract edge regions covered"""
    edge_cov = 0
    try:
        with tempfile.TemporaryDirectory() as asan_outdir:
            command = [
                coverage_binary,
                new_units_dir
            ]
            coverage_binary_dir = os.path.dirname(coverage_binary)
            env = os.environ.copy()

            data_dir = ":coverage_dir=" + asan_outdir
            if 'ASAN_OPTIONS' in env:
                env['ASAN_OPTIONS'] = env['ASAN_OPTIONS'] + ':coverage=1' + data_dir
            else:
                env['ASAN_OPTIONS'] = 'coverage=1' + data_dir

            result = new_process.execute(command,
                                         env=env,
                                         cwd=coverage_binary_dir,
                                         expect_zero=False,
                                         kill_children=True,
                                         timeout=MAX_TOTAL_TIME)

            if result.retcode != 0:
                logger.error('Coverage run failed.',
                             extras={
                                 'coverage_binary': coverage_binary,
                                 'output': result.output[-new_process.LOG_LIMIT_FIELD:],
                             })
            else:
                cov_file = None
                for file in os.listdir(asan_outdir):
                    if file.endswith(".sancov"):
                        cov_file = os.path.join(asan_outdir, file)
                        break

                command = [
                    'sancov',
                    '-print',
                    cov_file
                ]
                sancov_outfile_name =  os.path.join(asan_outdir, 'sancov_out.txt')
                sancov_outfile = open(sancov_outfile_name, "w")

                result = new_process.execute(command,
                                             env=env,
                                             cwd=asan_outdir,
                                             expect_zero=False,
                                             kill_children=True,
                                             output_file=sancov_outfile,
                                             timeout=MAX_TOTAL_TIME)


                #persist results of sancov
                coverage_directory = os.path.dirname(coverage_binary)
                shutil.copy(sancov_outfile.name,coverage_directory,False)


                sancov_outfile.close()
                edge_cov = sum(1 for line in open(sancov_outfile.name))
                print(coverage_binary, 'covered edges: ', edge_cov, sancov_outfile_name, cov_file)
    except Exception as e:
        print(e)
        pass
    return edge_cov


def do_coverage_run(  # pylint: disable=too-many-locals
        coverage_binary: str, new_units_dir: List[str],
        profraw_file_pattern: str, crashes_dir: str, sancov=False) -> List[str]:
    """Does a coverage run of |coverage_binary| on |new_units_dir|. Writes
    the result to |profraw_file_pattern|. Returns a list of crashing units."""

    with tempfile.TemporaryDirectory() as merge_dir:
        command = [
            coverage_binary, '-merge=1', '-dump_coverage=1',
            '-artifact_prefix=%s/' % crashes_dir,
            '-timeout=%d' % UNIT_TIMEOUT,
            '-rss_limit_mb=%d' % RSS_LIMIT_MB,
            '-max_total_time=%d' % (MAX_TOTAL_TIME - EXIT_BUFFER), merge_dir,
            new_units_dir
        ]
        coverage_binary_dir = os.path.dirname(coverage_binary)
        env = os.environ.copy()
        env['LLVM_PROFILE_FILE'] = profraw_file_pattern
        sanitizer.set_sanitizer_options(env)
        result = new_process.execute(command,
                                     env=env,
                                     cwd=coverage_binary_dir,
                                     expect_zero=False,
                                     kill_children=True,
                                     timeout=MAX_TOTAL_TIME)

    if result.retcode != 0:
        logger.error('Coverage run failed.',
                     extras={
                         'coverage_binary': coverage_binary,
                         'output': result.output[-new_process.LOG_LIMIT_FIELD:],
                     })
    return find_crashing_units(crashes_dir)


if __name__ == '__main__':
    coverage_binary = ''
    new_units_diro3 = ''
    new_units_diro0 = ''
    cov = get_coverage_sancov(coverage_binary, new_units_diro0)
    print(cov)
