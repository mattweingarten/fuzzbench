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
  fprintf(stderr, "StandaloneFuzzTargetMainDirectory: running %d inputs\n", argc - 1);

  if (LLVMFuzzerInitialize)
    LLVMFuzzerInitialize(&argc, &argv);

  if (argc > 1) {
    DIR *d;
    struct dirent *dir;
    d = opendir(argv[1]);
    char p[1000];
    int i = 0;
    if (d)
    {
        while ((dir = readdir(d)) != NULL)
        {
            if(dir->d_type==DT_REG){
                i++;
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
    fprintf(stderr, "Corpus had %d files\n", i);
  }
}
