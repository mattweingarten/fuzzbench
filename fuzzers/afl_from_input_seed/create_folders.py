#call this from afl_from_input_seed/ dir

import os
benchmarks = [f for f in os.scandir("../../benchmarks")]
for b in benchmarks:
    os.mkdir(os.path.basename(b.path))
# print(benchmarks)