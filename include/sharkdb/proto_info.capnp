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

@0xde07bf59f3ed73f2;

enum IntType {
    uint8 @0;
    uint16 @1;
    uint24 @2;
    uint32 @3;
    uint40 @4;
    uint48 @5;
    uint56 @6;
    uint64 @7;
    int8 @8;
    int16 @9;
    int24 @10;
    int32 @11;
    int40 @12;
    int48 @13;
    int56 @14;
    int64 @15;
    char @16;
}

enum FloatType {
    ieee11073Sfloat @0;
    ieee11073Float @1;
    float @2;
    double @3;
}

enum StringType {
    string @0;
    stringz @1;
    uintString @2;
    stringzPad @3;
    stringzTrunc @4;
}

enum IntDisplay {
    none @0;
    dec @1;
    hex @2;
    oct @3;
    decHex @4;
    hexDec @5;
    custom @6;
    udpPort @7;
    tcpPort @8;
    dccpPort @9;
    sctpPort @10;
    oui @11;
}

enum StringDisplay {
    ascii @0;
    unicode @1;
}

enum BytesSeparator {
    none @0;
    dot @1;
    dash @2;
    colon @3;
    space @4;
}

enum Ipv4Display {
    address @0;
    netmask @1;
}

struct ValueString {
    value @0 :UInt32;
    string @1 :Text;
}

struct Val64String {
    value @0 :UInt64;
    string @1 :Text;
}

struct RangeString {
    min @0 :UInt32;
    max @1 :UInt32;
    string @2 :Text; 
}

struct Field {
    name @0 :Text;
    abbrev @1 :Text;
    description :union {
        none @2 :Void;
        some @3 :Text;
    }
    bitmask @4 :UInt64;
    typeInfo :union {
        none @5 :Void;
        protocol :group {
            protoName :union {
                none @6 :Void;
                some @7 :Text;
            }
        }
        boolean :group {
            strings :union {
                none @8 :Void;
                some :group {
                    true @9 :Text;
                    false @10 :Text;
                }
            }
        }
        int :group {
            type @11 :IntType;
            strings :union {
                none @12 :Void;
                some32 @13 :List(ValueString);
                some64 @14 :List(Val64String);
                someRange @15 :List(RangeString);
                someUnit :group {
                    singular @16 :Text;
                    plural :union {
                        none @17 :Void;
                        some @18 :Text;
                    }
                }
            }
            display @19 :IntDisplay;
        }
        float :group {
            type @20 :FloatType;
            strings :union {
                none @21 :Void;
                some :group {
                    singular @22 :Text;
                    plural :union {
                        none @23 :Void;
                        some @24 :Text;
                    }
                }
            }
        }
        time :group {
            isRelative @25 :Bool;
        }
        string :group {
            type @26 :StringType;
            display @27 :StringDisplay;
        }
        bytes :group {
            isUint @28 :Bool;
            separator @29 :BytesSeparator;
        }
        framenum @30 :Void;
        eui64 @31 :Void;
        ipv4 :group {
            display @32 :Ipv4Display;
        }
        ipv6 @33 :Void;
        fcwwn @34 :Void;
        ether @35 :Void;
        guid @36 :Void;
        relOid @37 :Void;
        oid @38 :Void;
        systemId @39 :Void;
        ipxnet @40 :Void;
        ax25 @41 :Void;
        vines @42 :Void;
    }
}

struct HeurDissector {
    listName @0 :Text;
    shortName @1 :Text;
    displayName @2 :Text;
    enabled @3 :Bool;
}

struct Proto {
    shortName @0 :Text;
    longName @1 :Text;
    filterName @2 :Text;
    enabled @3 :Bool;
    canDisable @4 :Bool;
    isPino @5 :Bool;
    heuristicDissectors @6 :List(HeurDissector);
    fields @7 :List(Field);
}
