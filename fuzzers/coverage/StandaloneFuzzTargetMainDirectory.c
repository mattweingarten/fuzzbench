/*===- StandaloneFuzzTargetMain.c - standalone main() for fuzz targets. ---===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
// This main() function can be linked to a fuzz target (i.e. a library
// that exports LLVMFuzzerTestOneInput() and possibly LLVMFuzzerInitialize())
// instead of libFuzzer. This main() function will not perform any fuzzing
// but will simply feed all input files one by one to the fuzz target.
//
// Use this file to provide reproducers for bugs when linking against libFuzzer
// or other fuzzing engine is undesirable.
//===----------------------------------------------------------------------===*/
#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <dirent.h>
#include <errno.h>
#include <sys/stat.h>
#include<string.h>

extern int LLVMFuzzerTestOneInput(const unsigned char *data, size_t size);
__attribute__((weak)) extern int LLVMFuzzerInitialize(int *argc, char ***argv);
int main(int argc, char **argv) {
  fprintf(stderr, "StandaloneFuzzTargetMain: running %d inputs\n", argc - 1);

  if (LLVMFuzzerInitialize)
    LLVMFuzzerInitialize(&argc, &argv);

  if (argc > 1) {
    DIR *d;
    struct dirent *dir;
    d = opendir(argv[1]);
    char p[1000];
    if (d)
    {
        while ((dir = readdir(d)) != NULL)
        {
            if(dir->d_type==DT_REG){
                p[0]='\0';
                strcat(p, argv[1]);
                strcat(p,"/");
                strcat(p,dir->d_name);
                {
                    fprintf(stderr, "Running: %s\n", p);
                    FILE *f = fopen(p, "r");
                    assert(f);
                    fseek(f, 0, SEEK_END);
                    size_t len = ftell(f);
                    fseek(f, 0, SEEK_SET);
                    unsigned char *buf = (unsigned char*)malloc(len);
                    size_t n_read = fread(buf, 1, len, f);
                    fclose(f);
                    assert(n_read == len);
                    LLVMFuzzerTestOneInput(buf, len);
                    free(buf);
                    fprintf(stderr, "Done:    %s: (%zd bytes)\n", p, n_read);
                }
            }
        }
        closedir(d);
    }
  }
}
