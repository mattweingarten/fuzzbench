from fuzzers.aflplusplus import fuzzer as aflplusplus_fuzzer
import os
from fuzzers.aflplusplus_ast_opt_base.fuzzer import build_base_opt


def build():
    """Build benchmark."""
    os.environ['AFL_DONT_OPTIMIZE'] = '1'
    os.environ['AST_OPT_FLAGS'] = "--simplifycfg"
    build_base_opt()


def fuzz(input_corpus, output_corpus, target_binary):
    """Run fuzzer."""
    run_options = []
    aflplusplus_fuzzer.fuzz(input_corpus,
                            output_corpus,
                            target_binary,
                            flags=(run_options))
