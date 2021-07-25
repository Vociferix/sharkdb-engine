@0xe962ca985a4efadb;

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
    name :union {
        none @0 :Void;
        some @1 :Text;
    }
    description :union {
        none @2 :Void;
        some @3 :Text;
    }
    speed :union {
        none @4 :Void;
        some @5 :UInt64;
    }
    tsresol :union {
        none @6 :Void;
        some @7 :UInt8;
    }
    os :union {
        none @8 :Void;
        some @9 :Text;
    }
    fcslen :union {
        none @10 :Void;
        some @11 :UInt8;
    }
    hardware :union {
        none @12 :Void;
        some @13 :Text;
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
