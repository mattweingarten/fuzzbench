#!/usr/bin/env bash

DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]:-$0}"; )" &> /dev/null && pwd 2> /dev/null; )";

AST_OPT_CLANG_FLAGS=${AST_OPT_CLANG_FLAGS:-"-save-temps=obj -flto -O1 -Xclang -disable-llvm-passes"}
# AST_OPT_FLAGS=${AST_OPT_FLAGS:-"--simplifycfg"}
AST_OPT_CC=${AST_OPT_CC:-"clang"}

if [[ -z "$AST_OPT_FLAGS" ]]; then
    echo "AST_OPT_FLAGS must be set" 1>&2
    exit 1
fi

set -x
$AST_OPT_CC "$@" $AST_OPT_CLANG_FLAGS
set +x

for arg in "$@"
do
    if [[ "$arg" == *.o ]]
    then
        if [[ -n "$AST_OPT_FLAGS"  ]]
        then
            set -x
            opt $AST_OPT_FLAGS $arg -o $arg
            set +x
        fi
    fi
done
