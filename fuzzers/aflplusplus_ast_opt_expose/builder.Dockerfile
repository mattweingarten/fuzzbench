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

ARG parent_image
FROM $parent_image

# Install libstdc++ to use llvm_mode.
RUN apt-get update && \
    apt-get install -y wget libstdc++-5-dev libtool-bin automake flex bison \
                       libpixman-1-dev python3-setuptools unzip \
                       apt-utils apt-transport-https ca-certificates ninja

RUN apt-get install -y libglib2.0-dev python-pip
RUN pip3 install wllvm

ENV LLVM_COMPILER=clang


# Download and compile afl++.
RUN git clone https://github.com/mattweingarten/AFLplusplus /afl && \
    cd /afl && \
    git checkout stable-ast-modified


#build llvm for llvm-link
# RUN git clone https://github.com/llvm/llvm-project.git /llvm && \
#     cd /llvm && cmake -S llvm -B build -G ninja


# Build without Python support as we don't need it.
# Set AFL_NO_X86 to skip flaky tests.
RUN cd /afl && unset CFLAGS && unset CXXFLAGS && \
    export CC=clang && export AFL_NO_X86=1 && \
    PYTHON_INCLUDE=/ make -j8 && make install && \
    make -C utils/aflpp_driver && \
    cp utils/aflpp_driver/libAFLDriver.a /

RUN wget https://github.com/llvm/llvm-project/releases/download/llvmorg-12.0.0/clang+llvm-12.0.0-x86_64-linux-gnu-ubuntu-16.04.tar.xz -O /llvm.tar.xz
RUN tar -xf /llvm.tar.xz
RUN cp /afl/utils/llvm_opt_wrapper/post_process /out/
# RUN
# wllvm
# RUN pip3 install --upgrade pip
