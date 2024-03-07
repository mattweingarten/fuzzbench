#!/usr/bin/env bash

DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]:-$0}"; )" &> /dev/null && pwd 2> /dev/null; )";

AST_OPT_CLANG_FLAGS=${AST_OPT_CLANG_FLAGS:-"-save-temps=obj -flto -O1 -Xclang -disable-llvm-passes"}
AST_OPT_CXX=${AST_OPT_CXX:-"clang++"}

set -x
$AST_OPT_CXX "$@" $AST_OPT_CLANG_FLAGS
set +x
