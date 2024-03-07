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

ADD StandaloneFuzzTargetMainDirectory.c /
RUN clang -g -O2 -fno-omit-frame-pointer /StandaloneFuzzTargetMainDirectory.c -fPIC -c -o /libFuzzer.a
RUN cp /libFuzzer.a /usr/lib


