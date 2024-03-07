from fuzzers.aflplusplus import fuzzer as aflplusplus_fuzzer
import os
from fuzzers.aflplusplus_ast_opt_base.fuzzer import build_base_opt
# This is essentially O3, with a few Flags taken out: 
        # --loop-unroll\
        # --loop-vectorize\
        # --loop-simplify\
        # --slp-vectorizer\
        # --aggressive-instcombine\
        # --simplifycfg\

def build():
    """Build benchmark."""
    os.environ['AFL_DONT_OPTIMIZE'] = '1'
    os.environ['AST_OPT_FLAGS'] = """
        --aa\
        --adce\
        --alignment-from-assumptions\
        --argpromotion\
        --assumption-cache-tracker\
        --attributor\
        --barrier\
        --basic-aa\
        --basiccg\
        --bdce\
        --block-freq\
        --branch-prob\
        --called-value-propagation\
        --callsite-splitting\
        --constmerge\
        --correlated-propagation\
        --deadargelim\
        --demanded-bits\
        --div-rem-pairs\
        --domtree\
        --dse\
        --early-cse-memssa\
        --early-cse\
        --ee-instrument\
        --elim-avail-extern\
        --float2int\
        --forceattrs\
        --function-attrs\
        --globaldce\
        --globalopt\
        --globals-aa\
        --gvn\
        --indvars\
        --inferattrs\
        --inline\
        --instcombine\
        --instsimplify\
        --ipsccp\
        --jump-threading\
        --lazy-block-freq\
        --lazy-branch-prob\
        --lazy-value-info\
        --lcssa-verification\
        --lcssa\
        --libcalls-shrinkwrap\
        --licm\
        --loop-accesses\
        --loop-deletion\
        --loop-distribute\
        --loop-idiom\
        --loop-load-elim\
        --loop-rotate\
        --loop-sink\
        --loop-unswitch\
        --loops\
        --lower-constant-intrinsics\
        --lower-expect\
        --mem2reg\
        --memcpyopt\
        --memdep\
        --memoryssa\
        --mldst-motion\
        --opt-remark-emitter\
        --pgo-memop-opt\
        --phi-values\
        --postdomtree\
        --profile-summary-info\
        --prune-eh\
        --reassociate\
        --rpo-functionattrs\
        --scalar-evolution\
        --sccp\
        --scoped-noalias-aa\
        --speculative-execution\
        --sroa\
        --strip-dead-prototypes\
        --tailcallelim\
        --targetlibinfo\
        --tbaa\
        --transform-warning\
        --tti\
        --verify
    """
    build_base_opt()


def fuzz(input_corpus, output_corpus, target_binary):
    """Run fuzzer."""
    run_options = []
    aflplusplus_fuzzer.fuzz(input_corpus,
                            output_corpus,
                            target_binary,
                            flags=(run_options))
