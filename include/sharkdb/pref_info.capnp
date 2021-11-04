# This interface is distrubuted under either of the MIT or
# Apache v2.0 license by choice of the user.
#
# --------------------------------------------------------------------------------
# --------------------------------------------------------------------------------
#
# The MIT License (MIT)
# Copyright (c) 2021 Jack Bernard
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of
# this software and associated documentation files (the "Software"), to deal in
# the Software without restriction, including without limitation the rights to
# use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
# the Software, and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
# FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
# COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
# IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#
# --------------------------------------------------------------------------------
#                                     OR
# --------------------------------------------------------------------------------
# 
# Copyright 2021 Jack Bernard
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# --------------------------------------------------------------------------------
# --------------------------------------------------------------------------------

@0xee73e8bbe974a9b9;

struct Choice {
    name @0 :Text;
    description :union {
        none @1 :Void;
        some @2 :Text;
    }
    value @3 :Int32;
}

struct Range {
    low @0 :UInt32;
    high @1 :UInt32;
}

struct Pref {
    name :union {
        none @0 :Void;
        some @1 :Text;
    }
    title :union {
        none @2 :Void;
        some @3 :Text;
    }
    description :union {
        none @4 :Void;
        some @5 :Text;
    }
    typeName :union {
        none @6 :Void;
        some @7 :Text;
    }
    value :union {
        typeUnknown @8 :Void;
        typeUint :group {
            base @9 :UInt8;
            init @10 :UInt32;
        }
        typeBool :group {
            init @11 :Bool;
        }
        typeEnum :group {
            choices @12 :List(Choice);
            init @13 :Int32;
        }
        typeString :group {
            init :union {
                none @14 :Void;
                some @15 :Text;
            }
        }
        typeRange :group {
            max @16 :UInt32;
            init @17 :List(Range);
        }
        typeStaticText @18 :Void;
        typeUat @19 :Void;
        typeSaveFilename :group {
            init :union {
                none @20 :Void;
                some @21 :Text;
            }
        }
        typeDirname :group {
            init :union {
                none @22 :Void;
                some @23 :Text;
            }
        }
        typeOpenFilename :group {
            init :union {
                none @24 :Void;
                some @25 :Text;
            }
        }
    }
}

struct PrefModule {
    name :union {
        none @0 :Void;
        some @1 :Text;
    }
    title :union {
        none @2 :Void;
        some @3 :Text;
    }
    description :union {
        none @4 :Void;
        some @5 :Text;
    }
    prefs @6 :List(Pref);
    submodules @7 :List(PrefModule);
}

struct PrefInfo {
    modules @0 :List(PrefModule);
}
