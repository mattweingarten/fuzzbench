# Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Integration code for AFLplusplus fuzzer."""

# This optimized afl++ variant should always be run together with
# "aflplusplus" to show the difference - a default configured afl++ vs.
# a hand-crafted optimized one. afl++ is configured not to enable the good
# stuff by default to be as close to vanilla afl as possible.
# But this means that the good stuff is hidden away in this benchmark
# otherwise.

import os
import shutil

from fuzzers.aflplusplus import fuzzer as aflplusplus_fuzzer

def build():
    """Build benchmark."""
    os.environ['AFL_DONT_OPTIMIZE'] = '1'
    os.environ['AST_CC_ARGS'] = '-O3'
    aflplusplus_fuzzer.build()


def fuzz(input_corpus, output_corpus, target_binary):
    """Run fuzzer."""
    run_options = []

    #Copy starting seed to input corpus
    count = 0
    print(input_corpus)
    starting_seed_corpus = "/src/fuzzers/" + os.environ['FUZZER'] + '/' +  os.environ['BENCHMARK'] + '/' + 'corpus/'
    print(starting_seed_corpus)
    for f in os.listdir(starting_seed_corpus):
        os.system("tar -xvf --overwrite " +  starting_seed_corpus + f +  " -C" + '/tmp/')
        print(os.listdir("/tmp/seeds"))
        for seed in os.listdir("/tmp/seeds"):
            os.rename("/tmp/seeds/" + seed, "/tmp/seeds/" + str(count))
            shutil.copy("/tmp/seeds/" + str(count), "/out/seeds/", follow_symlinks=False)
            count += 1
        print(os.listdir("/tmp/seeds"))


    print("Len of seeds: " + str(len([ f in os.listdir("/out/seeds/")])))
    print(count)
    # for f in os.listdir()



    aflplusplus_fuzzer.fuzz(input_corpus,
                            output_corpus,
                            target_binary,
                            flags=(run_options))
