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

@0xe962ca985a4efadb;

enum Encap {
    unknown @0;
    ethernet @1;
    tokenRing @2;
    slip @3;
    ppp @4;
    fddi @5;
    fddiBitswapped @6;
    rawIp @7;
    arcnet @8;
    arcnetLinux @9;
    atmRfc1483 @10;
    linuxAtmClip @11;
    lapb @12;
    atmPdus @13;
    atmPdusUntruncated @14;
    null @15;
    ascend @16;
    isdn @17;
    ipOverFc @18;
    pppWithPhdr @19;
    ieee80211 @20;
    ieee80211Prism @21;
    ieee80211WithRadio @22;
    ieee80211Radiotap @23;
    ieee80211Avs @24;
    sll @25;
    frelay @26;
    frelayWithPhdr @27;
    chdlc @28;
    ciscoIos @29;
    localtalk @30;
    oldPflog @31;
    hhdlc @32;
    docsis @33;
    cosine @34;
    wfleetHdlc @35;
    sdlc @36;
    tzsp @37;
    enc @38;
    pflog @39;
    chdlcWithPhdr @40;
    bluetoothH4 @41;
    mtp2 @42;
    mtp3 @43;
    irda @44;
    user0 @45;
    user1 @46;
    user2 @47;
    user3 @48;
    user4 @49;
    user5 @50;
    user6 @51;
    user7 @52;
    user8 @53;
    user9 @54;
    user10 @55;
    user11 @56;
    user12 @57;
    user13 @58;
    user14 @59;
    user15 @60;
    symantec @61;
    appleIpOverIeee1394 @62;
    bacnetMsTp @63;
    nettlRawIcmp @64;
    nettlRawIcmpv6 @65;
    gprsLlc @66;
    juniperAtm1 @67;
    juniperAtm2 @68;
    redback @69;
    nettlRawIp @70;
    nettlEthernet @71;
    nettlTokenRing @72;
    nettlFddi @73;
    nettlUnknown @74;
    mtp2WithPhdr @75;
    juniperPppoe @76;
    gcomTie1 @77;
    gcomSerial @78;
    nettlX25 @79;
    k12 @80;
    juniperMlppp @81;
    juniperMlfr @82;
    juniperEther @83;
    juniperPpp @84;
    juniperFrelay @85;
    juniperChdlc @86;
    juniperGgsn @87;
    linuxLapd @88;
    catapultDct2000 @89;
    ber @90;
    juniperVp @91;
    usbFreebsd @92;
    ieee80216MacCps @93;
    nettlRawTelnet @94;
    usbLinux @95;
    mpeg @96;
    ppi @97;
    erf @98;
    bluetoothH4WithPhdr @99;
    sita @100;
    sccp @101;
    bluetoothHci @102;
    ipmbKontron @103;
    ieee802154 @104;
    x2EXoraya @105;
    flexray @106;
    lin @107;
    most @108;
    can20B @109;
    layer1Event @110;
    x2ESerial @111;
    i2CLinux @112;
    ieee802154NonaskPhy @113;
    tnef @114;
    usbLinuxMmapped @115;
    gsmUm @116;
    dpnss @117;
    packetlogger @118;
    nstrace10 @119;
    nstrace20 @120;
    fibreChannelFc2 @121;
    fibreChannelFc2WithFrameDelims @122;
    jpegJfif @123;
    ipnet @124;
    socketcan @125;
    ieee80211Netmon @126;
    ieee802154Nofcs @127;
    rawIpfix @128;
    rawIp4 @129;
    rawIp6 @130;
    lapd @131;
    dvbci @132;
    mux27010 @133;
    mime @134;
    netanalyzer @135;
    netanalyzerTransparent @136;
    ipOverIbSnoop @137;
    mpeg2Ts @138;
    pppEther @139;
    nfcLlcp @140;
    nflog @141;
    v5Ef @142;
    bacnetMsTpWithPhdr @143;
    ixveriwave @144;
    sdh @145;
    dbus @146;
    ax25Kiss @147;
    ax25 @148;
    sctp @149;
    infiniband @150;
    juniperSvcs @151;
    usbpcap @152;
    rtacSerial @153;
    bluetoothLeLl @154;
    wiresharkUpperPdu @155;
    stanag4607 @156;
    stanag5066DPdu @157;
    netlink @158;
    bluetoothLinuxMonitor @159;
    bluetoothBredrBb @160;
    bluetoothLeLlWithPhdr @161;
    nstrace30 @162;
    logcat @163;
    logcatBrief @164;
    logcatProcess @165;
    logcatTag @166;
    logcatThread @167;
    logcatTime @168;
    logcatThreadtime @169;
    logcatLong @170;
    pktap @171;
    epon @172;
    ipmiTrace @173;
    loop @174;
    json @175;
    nstrace35 @176;
    iso14443 @177;
    gfpT @178;
    gfpF @179;
    ipOverIbPcap @180;
    juniperVn @181;
    usbDarwin @182;
    loratap @183;
    ethernet3Mb @184;
    vsock @185;
    nordicBle @186;
    netmonNetNetevent @187;
    netmonHeader @188;
    netmonNetFilter @189;
    netmonNetworkInfoEx @190;
    maWfpCaptureV4 @191;
    maWfpCaptureV6 @192;
    maWfpCapture2V4 @193;
    maWfpCapture2V6 @194;
    maWfpCaptureAuthV4 @195;
    maWfpCaptureAuthV6 @196;
    juniperSt @197;
    ethernetMpacket @198;
    docsis31Xra31 @199;
    dpauxmon @200;
    rubyMarshal @201;
    rfc7468 @202;
    systemdJournal @203;
    ebhscr @204;
    vpp @205;
    ieee802154Tap @206;
    log3Gpp @207;
    usb20 @208;
    mp4 @209;
    sll2 @210;
    zwaveSerial @211;
    perPacket @212;
}

enum FileType {
    unknown @0;
    pcap @1;
    pcapng @2;
    pcapNsec @3;
    pcapAix @4;
    pcapSs991029 @5;
    pcapNokia @6;
    pcapSs990417 @7;
    pcapSs990915 @8;
    views5 @9;
    iptrace10 @10;
    iptrace20 @11;
    ber @12;
    hcidump @13;
    catapultDct2000 @14;
    netxrayOld @15;
    netxray10 @16;
    cosine @17;
    csids @18;
    dbsEtherwatch @19;
    erf @20;
    eyesdn @21;
    nettl @22;
    iseries @23;
    iseriesUnicode @24;
    i4Btrace @25;
    ascend @26;
    netmon1X @27;
    netmon2X @28;
    ngsnifferUncompressed @29;
    ngsnifferCompressed @30;
    netxray11 @31;
    netxray200X @32;
    networkInstruments @33;
    lanalyzer @34;
    pppdump @35;
    radcom @36;
    snoop @37;
    shomiti @38;
    vms @39;
    k12 @40;
    toshiba @41;
    visualNetworks @42;
    peekclassicV56 @43;
    peekclassicV7 @44;
    peektagged @45;
    mpeg @46;
    k12Text @47;
    netscreen @48;
    commview @49;
    btsnoop @50;
    tnef @51;
    dct3Trace @52;
    packetlogger @53;
    daintreeSna @54;
    netscaler10 @55;
    netscaler20 @56;
    jpegJfif @57;
    ipfix @58;
    mime @59;
    aethra @60;
    mpeg2Ts @61;
    vwr80211 @62;
    vwrEth @63;
    camins @64;
    stanag4607 @65;
    netscaler30 @66;
    logcat @67;
    logcatBrief @68;
    logcatProcess @69;
    logcatTag @70;
    logcatThread @71;
    logcatTime @72;
    logcatThreadtime @73;
    logcatLong @74;
    colasoftCapsa @75;
    colasoftPacketBuilder @76;
    json @77;
    netscaler35 @78;
    nettrace3Gpp32423 @79;
    mplog @80;
    dpa400 @81;
    rfc7468 @82;
    rubyMarshal @83;
    systemdJournal @84;
    log3Gpp @85;
    mp4 @86;
}

enum TSPrec {
    unknown @0;
    perPacket @1;
    sec @2;
    dsec @3;
    csec @4;
    msec @5;
    usec @6;
    nsec @7;
}

struct EthPHdr {
    fcsLen @0 :Int32;
}

struct DteDcePHdr {
    flags @0 :UInt8;
}

struct IsdnPHdr {
    uton @0 :Bool;
    channel @1 :UInt8;
}

struct AtmPHdr {
    flags @0 :UInt32;
    aal @1 :UInt8;
    type @2 :UInt8;
    subtype @3 :UInt8;
    vpi @4 :UInt16;
    vci @5 :UInt16;
    aal2Cid @6 :UInt8;
    channel @7 :UInt16;
    cells @8 :UInt16;
    aal5tU2u @9 :UInt16;
    aal5tLen @10 :UInt16;
    aal5tChksum @11 :UInt32;
}

struct AscendPHdr {
    type @0 :UInt16;
    user @1 :Text;
    sess @2 :UInt32;
    callNum @3 :Text;
    chunk @4 :UInt32;
    task @5 :UInt32;
}

struct P2PPHdr {
    sent @0 :Bool;
}

struct Ieee80211Fhss {
    hopSet :union {
        none @0 :Void;
        some @1 :UInt8;
    }
    hopPattern :union {
        none @2 :Void;
        some @3 :UInt8;
    }
    hopIndex :union {
        none @4 :Void;
        some @5 :UInt8;
    }
}

struct Ieee80211b {
    shortPreamble :union {
        none @0 :Void;
        some @1 :Bool;
    }
}

struct Ieee80211a {
    channelType :union {
        none @0 :Void;
        some @1 :UInt8;
    }
    turboType :union {
        none @2 :Void;
        some @3 :UInt8;
    }
}

struct Ieee80211g {
    shortPreamble :union {
        none @0 :Void;
        some @1 :Bool;
    }
    mode :union {
        none @2 :Void;
        some @3 :UInt32;
    }
}

struct Ieee80211n {
    mcsIndex :union {
        none @0 :Void;
        some @1 :UInt16;
    }
    bandwidth :union {
        none @2 :Void;
        some @3 :UInt32;
    }
    shortGi :union {
        none @4 :Void;
        some @5 :Bool;
    }
    greenfield :union {
        none @6 :Void;
        some @7 :Bool;
    }
    fec :union {
        none @8 :Void;
        some @9 :Bool;
    }
    stbcStreams :union {
        none @10 :Void;
        some @11 :UInt8;
    }
    ness :union {
        none @12 :Void;
        some @13 :UInt32;
    }
}

struct Ieee80211ac {
    stbc :union {
        none @0 :Void;
        some @1 :Bool;
    }
    txopPsNotAllowed :union {
        none @2 :Void;
        some @3 :Bool;
    }
    shortGi :union {
        none @4 :Void;
        some @5 :Bool;
    }
    shortGiNsymDisambig :union {
        none @6 :Void;
        some @7 :Bool;
    }
    ldpcExtraOfdmSymbol :union {
        none @8 :Void;
        some @9 :Bool;
    }
    beamformed :union {
        none @10 :Void;
        some @11 :Bool;
    }
    bandwidth :union {
        none @12 :Void;
        some @13 :UInt8;
    }
    mcs0 @14 :UInt8;
    mcs1 @15 :UInt8;
    mcs2 @16 :UInt8;
    mcs3 @17 :UInt8;
    nss0 @18 :UInt8;
    nss1 @19 :UInt8;
    nss2 @20 :UInt8;
    nss3 @21 :UInt8;
    fec :union {
        none @22 :Void;
        some @23 :UInt8;
    }
    groupId :union {
        none @24 :Void;
        some @25 :UInt8;
    }
    partialAid :union {
        none @26 :Void;
        some @27 :UInt16;
    }
}

struct Ieee80211ad {
    mcs :union {
        none @0 :Void;
        some @1 :UInt8;
    }
}

struct Ieee80211ax {
    nsts @0 :UInt8;
    mcs :union {
        none @1 :Void;
        some @2 :UInt8;
    }
    bwru :union {
        none @3 :Void;
        some @4 :UInt8;
    }
    gi :union {
        none @5 :Void;
        some @6 :UInt8;
    }
}

struct Ieee80211PHdr {
    fcsLen @0 :Int32;
    decrypted @1 :Bool;
    datapad @2 :Bool;
    noAMsdus @3 :Bool;
    phy @4 :UInt32;
    phyInfo :union {
        none @5 :Void;
        info11fhss @6 :Ieee80211Fhss;
        info11b @7 :Ieee80211b;
        info11a @8 :Ieee80211a;
        info11g @9 :Ieee80211g;
        info11n @10 :Ieee80211n;
        info11ac @11 :Ieee80211ac;
        info11ad @12 :Ieee80211ad;
        info11ax @13 :Ieee80211ax;
    }
    channel :union {
        none @14 :Void;
        some @15 :UInt16;
    }
    frequency :union {
        none @16 :Void;
        some @17 :UInt32;
    }
    dataRate :union {
        none @18 :Void;
        some @19 :UInt16;
    }
    signalPercent :union {
        none @20 :Void;
        some @21 :UInt8;
    }
    noisePercent :union {
        none @22 :Void;
        some @23 :UInt8;
    }
    signalDbm :union {
        none @24 :Void;
        some @25 :Int8;
    }
    noiseDbm :union {
        none @26 :Void;
        some @27 :Int8;
    }
    signalDb :union {
        none @28 :Void;
        some @29 :UInt8;
    }
    noiseDb :union {
        none @30 :Void;
        some @31 :UInt8;
    }
    tsfTimestamp :union {
        none @32 :Void;
        some @33 :UInt64;
    }
    aggregateInfo :union {
        none @34 :Void;
        some :group {
            flags @35 :UInt32;
            id @36 :UInt32;
        }
    }
    zeroLengthPsduType :union {
        none @37 :Void;
        some @38 :UInt8;
    }
}

struct CosinePHdr {
    encap @0 :UInt8;
    direction @1 :UInt8;
    ifName @2 :Text;
    pro @3 :UInt16;
    off @4 :UInt16;
    pri @5 :UInt16;
    rm @6 :UInt16;
    err @7 :UInt16;
}

struct IrdaPHdr {
    pkttype @0 :UInt16;
}

struct NettlPHdr {
    subsys @0 :UInt16;
    devid @1 :UInt32;
    kind @2 :UInt32;
    pid @3 :Int32;
    uid @4 :UInt32;
}

struct Mtp2PHdr {
    sent @0 :UInt8;
    annexAUsed @1 :UInt8;
    linkNumber @2 :UInt16;
}

struct K12PHdr {
    input @0 :UInt32;
    inputName @1 :Text;
    stackFile @2 :Text;
    inputType @3 :UInt32;

    inputInfo :union {
        atm :group {
            vp @4 :UInt16;
            vc @5 :UInt16;
            cid @6 :UInt16;
        }
        ds0mask @7 :UInt32;
    }

    extraInfo @8 :Data;
}

struct LapdPHdr {
    pkttype @0 :UInt16;
    weNetwork @1 :UInt8;
}

struct ErfPHdr {
    ts @0 :UInt64;
    type @1 :UInt8;
    flags @2 :UInt8;
    rlen @3 :UInt16;
    lctr @4 :UInt16;
    wlen @5 :UInt16;
}

struct ErfMcPHdr {
    phdr @0 :ErfPHdr;
    ehdrList @1 :List(UInt64); # struct erf_ehdr
    subhdr @2 :UInt32;
}

struct SitaPHdr {
    flags @0 :UInt8;
    signals @1 :UInt8;
    errors1 @2 :UInt8;
    errors2 @3 :UInt8;
    proto @4 :UInt8;
}

struct BthciPHdr {
    sent @0 :Bool;
    channel @1 :UInt32;
}

struct BtmonPHdr {
    adapterId @0 :UInt16;
    opcode @1 :UInt16;
}

struct L1EventPHdr {
    uton @0 :Bool;
}

struct I2CPHdr {
    isEvent @0 :UInt8;
    bus @1 :UInt8;
    flags @2 :UInt32;
}

struct GsmUmPHdr {
    uplink @0 :Bool;
    channel @1 :UInt8;
    bsic @2 :UInt8;
    arfcn @3 :UInt16;
    tdmaFrame @4 :UInt32;
    error @5 :UInt8;
    timeshift @6 :UInt16;
}

struct NstrPHdr {
    recOffset @0 :Int64;
    recLen @1 :Int32;
    nicnoOffset @2 :UInt8;
    nicnoLen @3 :UInt8;
    dirOffset @4 :UInt8;
    dirLen @5 :UInt8;
    ethOffset @6 :UInt16;
    pcbOffset @7 :UInt8;
    lPcbOffset @8 :UInt8;
    recType @9 :UInt8;
    vlantagOffset @10 :UInt8;
    coreidOffset @11 :UInt8;
    srcnodeidOffset @12 :UInt8;
    destnodeidOffset @13 :UInt8;
    clflagsOffset @14 :UInt8;
    srcVmnameLenOffset @15 :UInt8;
    dstVmnameLenOffset @16 :UInt8;
    nsActivityOffset @17 :UInt8;
    dataOffset @18 :UInt8;
}

struct NokiaPHdr {
    eth @0 :EthPHdr;
    stuff0 @1 :UInt8;
    stuff1 @2 :UInt8;
    stuff2 @3 :UInt8;
    stuff3 @4 :UInt8;
}

struct LlcpPHdr {
    adapter @0 :UInt8;
    flags @1 :UInt8;
}

struct LogcatPHdr {
    version @0 :Int32;
}

struct NetmonPHdr {
    title @0 :Text;
    descLength @1 :UInt32;
    description @2 :Text;
    subEncap @3 :UInt32;
    subheader :union {
        none @4 :Void;
        eth @5 :EthPHdr;
        atm @6 :AtmPHdr;
        ieee80211 @7 :Ieee80211PHdr;
    }
}

struct PacketHeader {
    len @0 :UInt32;
    pktEncap @1 :Int32;
    interfaceId @2 :UInt32;
    dropCount @3 :UInt64;
    packFlags @4 :UInt32;
    interfaceQueue @5 :UInt32;
    packetId @6 :UInt64;
    pseudoHeader :union {
        none @7 :Void;
        eth @8 :EthPHdr;
        dteDce @9 :DteDcePHdr;
        isdn @10 :IsdnPHdr;
        atm @11 :AtmPHdr;
        ascend @12 :AscendPHdr;
        p2p @13 :P2PPHdr;
        ieee80211 @14 :Ieee80211PHdr;
        cosine @15 :CosinePHdr;
        irda @16 :IrdaPHdr;
        nettl @17 :NettlPHdr;
        mtp2 @18 :Mtp2PHdr;
        k12 @19 :K12PHdr;
        lapd @20 :LapdPHdr;
        erf @21 :ErfMcPHdr;
        sita @22 :SitaPHdr;
        bthci @23 :BthciPHdr;
        btmon @24 :BtmonPHdr;
        l1event @25 :L1EventPHdr;
        i2c @26 :I2CPHdr;
        gsmUm @27 :GsmUmPHdr;
        nstr @28 :NstrPHdr;
        nokia @29 :NokiaPHdr;
        llcp @30 :LlcpPHdr;
        logcat @31 :LogcatPHdr;
        netmon @32 :NetmonPHdr;
    }
    data @33 :Data;
}

struct SyscallHeader {
    recordType @0 :UInt32;
    byteOrder @1 :Int32;
    timestamp @2 :UInt64;
    threadId @3 :UInt64;
    eventLen @4 :UInt32;
    eventType @5 :UInt16;
    nparams @6 :UInt32;
    cpuId @7 :UInt16;
    data @8 :Data;
}

struct SystemdJournalHeader {
    data @0 :Data;
}

struct Record {
    presenceFlags @0 :UInt32;
    ts :group {
        secs @1 :Int64;
        nsecs @2 :Int32;
    }
    tsprec @3 :Int32;
    recHeader :union {
        packetHeader @4 :PacketHeader;
        syscallHeader @5 :SyscallHeader;
        systemdJournalHeader @6 :SystemdJournalHeader;
    }
    optComment :union {
        none @7 :Void;
        some @8 :Text;
    }
    hasCommentChanged @9 :Bool;
    packetVerdict :union {
        none @10 :Void;
        some @11 :List(Data);
    }
    optionsBuf @12 :Data;
}

struct IPv4Host {
    addr @0 :Data;
    name @1 :Text;
}

struct IPv6Host {
    addr @0 :Data;
    name @1 :Text;
}

struct DecryptSecrets {
    type @0 :UInt32;
    secrets @1 :Data;
}

struct IfaceDesc {
    encap @0 :Int32;
    timeUnitsPerSecond @1 :UInt64;
    tsprecision @2 :TSPrec;
    snapLen @3 :UInt32;
    name :union {
        none @4 :Void;
        some @5 :Text;
    }
    description :union {
        none @6 :Void;
        some @7 :Text;
    }
    speed :union {
        none @8 :Void;
        some @9 :UInt64;
    }
    tsresol :union {
        none @10 :Void;
        some @11 :UInt8;
    }
    os :union {
        none @12 :Void;
        some @13 :Text;
    }
    fcslen :union {
        none @14 :Void;
        some @15 :UInt8;
    }
    hardware :union {
        none @16 :Void;
        some @17 :Text;
    }
}

struct CaptureEntry {
    union {
        record @0 :Record;
        iface @1 :IfaceDesc;
        ipv4Host @2 :IPv4Host;
        ipv6Host @3 :IPv6Host;
        secrets @4 :DecryptSecrets;
    }
}

struct CaptureInfo {
    filetype @0 :FileType;
    encap @1 :Encap;
    snaplen @2 :UInt32;
    tsprec @3 :TSPrec;
}
