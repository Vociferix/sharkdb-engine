#include "write.hpp"

#include <capnp/message.h>
#include <capnp/serialize.h>
#include <kj/std/iostream.h>
#include <wiretap/wtap.h>

#include <cstring>
#include <vector>

#include "sharkdb_read.capnp.h"

#ifdef _WIN32
#include <Ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <sys/socket.h>
#endif

namespace sharkdb {

template <typename T>
void destroy(gpointer data) {
    delete reinterpret_cast<T*>(data);
}

static int read_eth_phdr(EthPHdr::Reader phdr_in, eth_phdr& phdr) {
    phdr.fcs_len = phdr_in.getFcsLen();
    return 0;
}

static int read_dte_dce_phdr(DteDcePHdr::Reader phdr_in, dte_dce_phdr& phdr) {
    phdr.flags = phdr_in.getFlags();
    return 0;
}

static int read_isdn_phdr(IsdnPHdr::Reader phdr_in, isdn_phdr& phdr) {
    phdr.uton = phdr_in.getUton();
    phdr.channel = phdr_in.getChannel();
    return 0;
}

static int read_atm_phdr(AtmPHdr::Reader phdr_in, atm_phdr& phdr) {
    phdr.flags = phdr_in.getFlags();
    phdr.aal = phdr_in.getAal();
    phdr.type = phdr_in.getType();
    phdr.subtype = phdr_in.getSubtype();
    phdr.vpi = phdr_in.getVpi();
    phdr.vci = phdr_in.getVci();
    phdr.aal2_cid = phdr_in.getAal2Cid();
    phdr.channel = phdr_in.getChannel();
    phdr.cells = phdr_in.getCells();
    phdr.aal5t_u2u = phdr_in.getAal5tU2u();
    phdr.aal5t_len = phdr_in.getAal5tLen();
    phdr.aal5t_chksum = phdr_in.getAal5tChksum();
    return 0;
}

static int read_ascend_phdr(AscendPHdr::Reader phdr_in, ascend_phdr& phdr) {
    phdr.type = phdr_in.getType();
    auto user = phdr_in.getUser();
    std::size_t i = 0;
    while (i < user.size() && i < ASCEND_MAX_STR_LEN) {
        phdr.user[i] = user[i];
        ++i;
    }
    while (i < ASCEND_MAX_STR_LEN) { phdr.user[i++] = '\0'; }
    phdr.sess = phdr_in.getSess();
    auto call_num = phdr_in.getCallNum();
    i = 0;
    while (i < call_num.size() && i < ASCEND_MAX_STR_LEN) {
        phdr.call_num[i] = call_num[i];
        ++i;
    }
    while (i < ASCEND_MAX_STR_LEN) { phdr.call_num[i++] = '\0'; }
    phdr.chunk = phdr_in.getChunk();
    phdr.task = phdr_in.getTask();
    return 0;
}

static int read_p2p_phdr(P2PPHdr::Reader phdr_in, p2p_phdr& phdr) {
    phdr.sent = phdr_in.getSent() ? 1 : 0;
    return 0;
}

static int read_ieee_802_11_fhss_phdr(Ieee80211Fhss::Reader phdr_in, ieee_802_11_fhss& phdr) {
    auto hop_set = phdr_in.getHopSet();
    auto hop_pattern = phdr_in.getHopPattern();
    auto hop_index = phdr_in.getHopIndex();
    phdr.has_hop_set = 0;
    if (hop_set.isSome()) {
        phdr.has_hop_set = 1;
        phdr.hop_set = hop_set.getSome();
    }
    phdr.has_hop_pattern = 0;
    if (hop_pattern.isSome()) {
        phdr.has_hop_pattern = 1;
        phdr.hop_pattern = hop_pattern.getSome();
    }
    phdr.has_hop_index = 0;
    if (hop_index.isSome()) {
        phdr.has_hop_index = 1;
        phdr.hop_index = hop_index.getSome();
    }
    return 0;
}

static int read_ieee_802_11b_phdr(Ieee80211b::Reader phdr_in, ieee_802_11b& phdr) {
    auto short_preamble = phdr_in.getShortPreamble();
    phdr.has_short_preamble = 0;
    if (short_preamble.isSome()) {
        phdr.has_short_preamble = 1;
        phdr.short_preamble = short_preamble.getSome();
    }
    return 0;
}

static int read_ieee_802_11a_phdr(Ieee80211a::Reader phdr_in, ieee_802_11a& phdr) {
    auto channel_type = phdr_in.getChannelType();
    auto turbo_type = phdr_in.getTurboType();
    phdr.has_channel_type = 0;
    if (channel_type.isSome()) {
        phdr.has_channel_type = 1;
        phdr.channel_type = channel_type.getSome();
    }
    phdr.has_turbo_type = 0;
    if (turbo_type.isSome()) {
        phdr.has_turbo_type = 1;
        phdr.turbo_type = turbo_type.getSome();
    }
    return 0;
}

static int read_ieee_802_11g_phdr(Ieee80211g::Reader phdr_in, ieee_802_11g& phdr) {
    auto short_preamble = phdr_in.getShortPreamble();
    auto mode = phdr_in.getMode();
    phdr.has_short_preamble = 0;
    if (short_preamble.isSome()) {
        phdr.has_short_preamble = 1;
        phdr.short_preamble = short_preamble.getSome();
    }
    phdr.has_mode = 0;
    if (mode.isSome()) {
        phdr.has_mode = 1;
        phdr.mode = mode.getSome();
    }
    return 0;
}

static int read_ieee_802_11n_phdr(Ieee80211n::Reader phdr_in, ieee_802_11n& phdr) {
    auto mcs_index = phdr_in.getMcsIndex();
    auto bandwidth = phdr_in.getBandwidth();
    auto short_gi = phdr_in.getShortGi();
    auto greenfield = phdr_in.getGreenfield();
    auto fec = phdr_in.getFec();
    auto stbc_streams = phdr_in.getStbcStreams();
    auto ness = phdr_in.getNess();
    phdr.has_mcs_index = 0;
    if (mcs_index.isSome()) {
        phdr.has_mcs_index = 1;
        phdr.mcs_index = mcs_index.getSome();
    }
    phdr.has_bandwidth = 0;
    if (bandwidth.isSome()) {
        phdr.has_bandwidth = 1;
        phdr.bandwidth = bandwidth.getSome();
    }
    phdr.has_short_gi = 0;
    if (short_gi.isSome()) {
        phdr.has_short_gi = 1;
        phdr.short_gi = short_gi.getSome() ? 1 : 0;
    }
    phdr.has_greenfield = 0;
    if (greenfield.isSome()) {
        phdr.has_greenfield = 1;
        phdr.greenfield = greenfield.getSome() ? 1 : 0;
    }
    phdr.has_fec = 0;
    if (fec.isSome()) {
        phdr.has_fec = 1;
        phdr.fec = fec.getSome() ? 1 : 0;
    }
    phdr.has_stbc_streams = 0;
    if (stbc_streams.isSome()) {
        phdr.has_stbc_streams = 1;
        phdr.stbc_streams = stbc_streams.getSome();
    }
    phdr.has_ness = 0;
    if (ness.isSome()) {
        phdr.has_ness = 1;
        phdr.ness = ness.getSome();
    }
    return 0;
}

static int read_ieee_802_11ac_phdr(Ieee80211ac::Reader phdr_in, ieee_802_11ac& phdr) {
    auto stbc = phdr_in.getStbc();
    auto txop_ps_not_allowed = phdr_in.getTxopPsNotAllowed();
    auto short_gi = phdr_in.getShortGi();
    auto short_gi_nsym_disambig = phdr_in.getShortGiNsymDisambig();
    auto ldpc_extra_ofdm_symbol = phdr_in.getLdpcExtraOfdmSymbol();
    auto beamformed = phdr_in.getBeamformed();
    auto bandwidth = phdr_in.getBandwidth();
    auto fec = phdr_in.getFec();
    auto group_id = phdr_in.getGroupId();
    auto partial_aid = phdr_in.getPartialAid();
    phdr.has_stbc = 0;
    if (stbc.isSome()) {
        phdr.has_stbc = 1;
        phdr.stbc = stbc.getSome() ? 1 : 0;
    }
    phdr.has_txop_ps_not_allowed = 0;
    if (txop_ps_not_allowed.isSome()) {
        phdr.has_txop_ps_not_allowed = 1;
        phdr.txop_ps_not_allowed = txop_ps_not_allowed.getSome() ? 1 : 0;
    }
    phdr.has_short_gi = 0;
    if (short_gi.isSome()) {
        phdr.has_short_gi = 1;
        phdr.short_gi = short_gi.getSome() ? 1 : 0;
    }
    phdr.has_short_gi_nsym_disambig = 0;
    if (short_gi_nsym_disambig.isSome()) {
        phdr.has_short_gi_nsym_disambig = 1;
        phdr.short_gi_nsym_disambig = short_gi_nsym_disambig.getSome() ? 1 : 0;
    }
    phdr.has_ldpc_extra_ofdm_symbol = 0;
    if (ldpc_extra_ofdm_symbol.isSome()) {
        phdr.has_ldpc_extra_ofdm_symbol = 1;
        phdr.ldpc_extra_ofdm_symbol = ldpc_extra_ofdm_symbol.getSome() ? 1 : 0;
    }
    phdr.has_beamformed = 0;
    if (beamformed.isSome()) {
        phdr.has_beamformed = 1;
        phdr.beamformed = beamformed.getSome() ? 1 : 0;
    }
    phdr.has_bandwidth = 0;
    if (bandwidth.isSome()) {
        phdr.has_bandwidth = 1;
        phdr.bandwidth = bandwidth.getSome();
    }
    phdr.mcs[0] = phdr_in.getMcs0();
    phdr.mcs[1] = phdr_in.getMcs1();
    phdr.mcs[2] = phdr_in.getMcs2();
    phdr.mcs[3] = phdr_in.getMcs3();
    phdr.nss[0] = phdr_in.getNss0();
    phdr.nss[1] = phdr_in.getNss1();
    phdr.nss[2] = phdr_in.getNss2();
    phdr.nss[3] = phdr_in.getNss3();
    phdr.has_fec = 0;
    if (fec.isSome()) {
        phdr.has_fec = 1;
        phdr.fec = fec.getSome();
    }
    phdr.has_group_id = 0;
    if (group_id.isSome()) {
        phdr.has_group_id = 1;
        phdr.group_id = group_id.getSome();
    }
    phdr.has_partial_aid = 0;
    if (partial_aid.isSome()) {
        phdr.has_partial_aid = 1;
        phdr.partial_aid = partial_aid.getSome();
    }
    return 0;
}

static int read_ieee_802_11ad_phdr(Ieee80211ad::Reader phdr_in, ieee_802_11ad& phdr) {
    auto mcs = phdr_in.getMcs();
    phdr.has_mcs_index = 0;
    if (mcs.isSome()) {
        phdr.has_mcs_index = 1;
        phdr.mcs = mcs.getSome();
    }
    return 0;
}

static int read_ieee_802_11ax_phdr(Ieee80211ax::Reader phdr_in, ieee_802_11ax& phdr) {
    phdr.nsts = phdr_in.getNsts();
    auto mcs = phdr_in.getMcs();
    auto bwru = phdr_in.getBwru();
    auto gi = phdr_in.getGi();
    phdr.has_mcs_index = 0;
    if (mcs.isSome()) {
        phdr.has_mcs_index = 1;
        phdr.mcs = mcs.getSome();
    }
    phdr.has_bwru = 0;
    if (bwru.isSome()) {
        phdr.has_bwru = 1;
        phdr.bwru = bwru.getSome();
    }
    phdr.has_gi = 0;
    if (gi.isSome()) {
        phdr.has_gi = 1;
        phdr.gi = gi.getSome();
    }
    return 0;
}

static int read_ieee_802_11_phdr(Ieee80211PHdr::Reader phdr_in, ieee_802_11_phdr& phdr) {
    phdr.fcs_len = phdr_in.getFcsLen();
    phdr.decrypted = phdr_in.getDecrypted() ? 1 : 0;
    phdr.datapad = phdr_in.getDatapad() ? 1 : 0;
    phdr.no_a_msdus = phdr_in.getNoAMsdus() ? 1 : 0;
    phdr.phy = phdr_in.getPhy();

    auto phy_info = phdr_in.getPhyInfo();
    int rc = 0;
    switch (phy_info.which()) {
    case Ieee80211PHdr::PhyInfo::INFO11FHSS:
        rc = read_ieee_802_11_fhss_phdr(phy_info.getInfo11fhss(), phdr.phy_info.info_11_fhss);
        break;
    case Ieee80211PHdr::PhyInfo::INFO11B:
        rc = read_ieee_802_11b_phdr(phy_info.getInfo11b(), phdr.phy_info.info_11b);
        break;
    case Ieee80211PHdr::PhyInfo::INFO11A:
        rc = read_ieee_802_11a_phdr(phy_info.getInfo11a(), phdr.phy_info.info_11a);
        break;
    case Ieee80211PHdr::PhyInfo::INFO11G:
        rc = read_ieee_802_11g_phdr(phy_info.getInfo11g(), phdr.phy_info.info_11g);
        break;
    case Ieee80211PHdr::PhyInfo::INFO11N:
        rc = read_ieee_802_11n_phdr(phy_info.getInfo11n(), phdr.phy_info.info_11n);
        break;
    case Ieee80211PHdr::PhyInfo::INFO11AC:
        rc = read_ieee_802_11ac_phdr(phy_info.getInfo11ac(), phdr.phy_info.info_11ac);
        break;
    case Ieee80211PHdr::PhyInfo::INFO11AD:
        rc = read_ieee_802_11ad_phdr(phy_info.getInfo11ad(), phdr.phy_info.info_11ad);
        break;
    case Ieee80211PHdr::PhyInfo::INFO11AX:
        rc = read_ieee_802_11ax_phdr(phy_info.getInfo11ax(), phdr.phy_info.info_11ax);
        break;
    default:
        break;
    }

    auto channel = phdr_in.getChannel();
    auto frequency = phdr_in.getFrequency();
    auto data_rate = phdr_in.getDataRate();
    auto signal_percent = phdr_in.getSignalPercent();
    auto noise_percent = phdr_in.getNoisePercent();
    auto signal_dbm = phdr_in.getSignalDbm();
    auto noise_dbm = phdr_in.getNoiseDbm();
    auto signal_db = phdr_in.getSignalDb();
    auto noise_db = phdr_in.getNoiseDb();
    auto tsf_timestamp = phdr_in.getTsfTimestamp();
    auto aggregate_info = phdr_in.getAggregateInfo();
    auto zero_length_psdu_type = phdr_in.getZeroLengthPsduType();

    phdr.has_channel = 0;
    if (channel.isSome()) {
        phdr.has_channel = 1;
        phdr.channel = channel.getSome();
    }

    phdr.has_frequency = 0;
    if (frequency.isSome()) {
        phdr.has_frequency = 1;
        phdr.frequency = frequency.getSome();
    }

    phdr.has_data_rate = 0;
    if (data_rate.isSome()) {
        phdr.has_data_rate = 1;
        phdr.data_rate = data_rate.getSome();
    }

    phdr.has_signal_percent = 0;
    if (signal_percent.isSome()) {
        phdr.has_signal_percent = 1;
        phdr.signal_percent = signal_percent.getSome();
    }

    phdr.has_noise_percent = 0;
    if (noise_percent.isSome()) {
        phdr.has_noise_percent = 1;
        phdr.noise_percent = noise_percent.getSome();
    }

    phdr.has_signal_dbm = 0;
    if (signal_dbm.isSome()) {
        phdr.has_signal_dbm = 1;
        phdr.signal_dbm = signal_dbm.getSome();
    }

    phdr.has_noise_dbm = 0;
    if (noise_dbm.isSome()) {
        phdr.has_noise_dbm = 1;
        phdr.noise_dbm = noise_dbm.getSome();
    }

    phdr.has_signal_db = 0;
    if (signal_db.isSome()) {
        phdr.has_signal_db = 1;
        phdr.signal_db = signal_db.getSome();
    }

    phdr.has_noise_db = 0;
    if (noise_db.isSome()) {
        phdr.has_noise_db = 1;
        phdr.noise_db = noise_db.getSome();
    }

    phdr.has_tsf_timestamp = 0;
    if (tsf_timestamp.isSome()) {
        phdr.has_tsf_timestamp = 1;
        phdr.tsf_timestamp = tsf_timestamp.getSome();
    }

    phdr.has_aggregate_info = 0;
    if (aggregate_info.isSome()) {
        phdr.has_aggregate_info = 1;
        auto agg_info = aggregate_info.getSome();
        phdr.aggregate_flags = agg_info.getFlags();
        phdr.aggregate_id = agg_info.getId();
    }

    phdr.has_zero_length_psdu_type = 0;
    if (zero_length_psdu_type.isSome()) {
        phdr.has_zero_length_psdu_type = 1;
        phdr.zero_length_psdu_type = zero_length_psdu_type.getSome();
    }

    return rc;
}

static int read_cosine_phdr(CosinePHdr::Reader phdr_in, cosine_phdr& phdr) {
    phdr.encap = phdr_in.getEncap();
    phdr.direction = phdr_in.getDirection();
    auto if_name = phdr_in.getIfName();
    std::size_t i = 0;
    while (i < if_name.size() && i < COSINE_MAX_IF_NAME_LEN) {
        phdr.if_name[i] = if_name[i];
        ++i;
    }
    while (i < COSINE_MAX_IF_NAME_LEN) { phdr.if_name[i++] = '\0'; }
    phdr.pro = phdr_in.getPro();
    phdr.off = phdr_in.getOff();
    phdr.pri = phdr_in.getPri();
    phdr.rm = phdr_in.getRm();
    phdr.err = phdr_in.getErr();
    return 0;
}

static int read_irda_phdr(IrdaPHdr::Reader phdr_in, irda_phdr& phdr) {
    phdr.pkttype = phdr_in.getPkttype();
    return 0;
}

static int read_nettl_phdr(NettlPHdr::Reader phdr_in, nettl_phdr& phdr) {
    phdr.subsys = phdr_in.getSubsys();
    phdr.devid = phdr_in.getDevid();
    phdr.kind = phdr_in.getKind();
    phdr.pid = phdr_in.getPid();
    phdr.uid = phdr_in.getUid();
    return 0;
}

static int read_mtp2_phdr(Mtp2PHdr::Reader phdr_in, mtp2_phdr& phdr) {
    phdr.sent = phdr_in.getSent();
    phdr.annex_a_used = phdr_in.getAnnexAUsed();
    phdr.link_number = phdr_in.getLinkNumber();
    return 0;
}

static int read_k12_phdr(K12PHdr::Reader phdr_in, k12_phdr& phdr) {
    phdr.input = phdr_in.getInput();
    phdr.input_name = phdr_in.getInputName().cStr();
    phdr.stack_file = phdr_in.getStackFile().cStr();
    phdr.input_type = phdr_in.getInputType();
    auto input_info = phdr_in.getInputInfo();
    if (input_info.isAtm()) {
        auto atm = input_info.getAtm();
        phdr.input_info.atm.vp = atm.getVp();
        phdr.input_info.atm.vc = atm.getVc();
        phdr.input_info.atm.cid = atm.getCid();
    } else {
        phdr.input_info.ds0mask = input_info.getDs0mask();
    }
    auto extra_info = phdr_in.getExtraInfo();
    phdr.extra_info = const_cast<guint8*>(extra_info.begin());
    phdr.extra_length = static_cast<guint32>(extra_info.size());
    phdr.stuff = nullptr;
    return 0;
}

static int read_lapd_phdr(LapdPHdr::Reader phdr_in, lapd_phdr& phdr) {
    phdr.pkttype = phdr_in.getPkttype();
    phdr.we_network = phdr_in.getWeNetwork();
    return 0;
}

static int read_erf_mc_phdr(ErfMcPHdr::Reader phdr_in, erf_mc_phdr& phdr) {
    auto erf_phdr = phdr_in.getPhdr();
    phdr.phdr.ts = erf_phdr.getTs();
    phdr.phdr.type = erf_phdr.getType();
    phdr.phdr.flags = erf_phdr.getFlags();
    phdr.phdr.rlen = erf_phdr.getRlen();
    phdr.phdr.lctr = erf_phdr.getLctr();
    phdr.phdr.wlen = erf_phdr.getWlen();
    auto ehdrs = phdr_in.getEhdrList();
    std::size_t i = 0;
    while (i < ehdrs.size() && i < MAX_ERF_EHDR) {
        phdr.ehdr_list[i].ehdr = ehdrs[i];
        ++i;
    }
    while (i < MAX_ERF_EHDR) { phdr.ehdr_list[i++].ehdr = 0; }
    phdr.subhdr.mc_hdr = phdr_in.getSubhdr();
    return 0;
}

static int read_sita_phdr(SitaPHdr::Reader phdr_in, sita_phdr& phdr) {
    phdr.sita_flags = phdr_in.getFlags();
    phdr.sita_signals = phdr_in.getSignals();
    phdr.sita_errors1 = phdr_in.getErrors1();
    phdr.sita_errors2 = phdr_in.getErrors2();
    phdr.sita_proto = phdr_in.getProto();
    return 0;
}

static int read_bthci_phdr(BthciPHdr::Reader phdr_in, bthci_phdr& phdr) {
    phdr.sent = phdr_in.getSent() ? 1 : 0;
    phdr.channel = phdr_in.getChannel();
    return 0;
}

static int read_btmon_phdr(BtmonPHdr::Reader phdr_in, btmon_phdr& phdr) {
    phdr.adapter_id = phdr_in.getAdapterId();
    phdr.opcode = phdr_in.getOpcode();
    return 0;
}

static int read_l1event_phdr(L1EventPHdr::Reader phdr_in, l1event_phdr& phdr) {
    phdr.uton = phdr_in.getUton();
    return 0;
}

static int read_i2c_phdr(I2CPHdr::Reader phdr_in, i2c_phdr& phdr) {
    phdr.is_event = phdr_in.getIsEvent();
    phdr.bus = phdr_in.getBus();
    phdr.flags = phdr_in.getFlags();
    return 0;
}

static int read_gsm_um_phdr(GsmUmPHdr::Reader phdr_in, gsm_um_phdr& phdr) {
    phdr.uplink = phdr_in.getUplink() ? 1 : 0;
    phdr.channel = phdr_in.getChannel();
    phdr.bsic = phdr_in.getBsic();
    phdr.arfcn = phdr_in.getArfcn();
    phdr.tdma_frame = phdr_in.getTdmaFrame();
    phdr.error = phdr_in.getError();
    phdr.timeshift = phdr_in.getTimeshift();
    return 0;
}

static int read_nstr_phdr(NstrPHdr::Reader phdr_in, nstr_phdr& phdr) {
    phdr.rec_offset = phdr_in.getRecOffset();
    phdr.rec_len = phdr_in.getRecLen();
    phdr.nicno_offset = phdr_in.getNicnoOffset();
    phdr.nicno_len = phdr_in.getNicnoLen();
    phdr.dir_offset = phdr_in.getDirOffset();
    phdr.dir_len = phdr_in.getDirLen();
    phdr.eth_offset = phdr_in.getEthOffset();
    phdr.pcb_offset = phdr_in.getPcbOffset();
    phdr.l_pcb_offset = phdr_in.getLPcbOffset();
    phdr.rec_type = phdr_in.getRecType();
    phdr.vlantag_offset = phdr_in.getVlantagOffset();
    phdr.coreid_offset = phdr_in.getCoreidOffset();
    phdr.srcnodeid_offset = phdr_in.getSrcnodeidOffset();
    phdr.destnodeid_offset = phdr_in.getDestnodeidOffset();
    phdr.clflags_offset = phdr_in.getClflagsOffset();
    phdr.src_vmname_len_offset = phdr_in.getSrcVmnameLenOffset();
    phdr.dst_vmname_len_offset = phdr_in.getDstVmnameLenOffset();
    phdr.ns_activity_offset = phdr_in.getNsActivityOffset();
    phdr.data_offset = phdr_in.getDataOffset();
    return 0;
}

static int read_nokia_phdr(NokiaPHdr::Reader phdr_in, nokia_phdr& phdr) {
    auto rc = read_eth_phdr(phdr_in.getEth(), phdr.eth);
    phdr.stuff[0] = phdr_in.getStuff0();
    phdr.stuff[1] = phdr_in.getStuff1();
    phdr.stuff[2] = phdr_in.getStuff2();
    phdr.stuff[3] = phdr_in.getStuff3();
    return rc;
}

static int read_llcp_phdr(LlcpPHdr::Reader phdr_in, llcp_phdr& phdr) {
    phdr.adapter = phdr_in.getAdapter();
    phdr.flags = phdr_in.getFlags();
    return 0;
}

static int read_logcat_phdr(LogcatPHdr::Reader phdr_in, logcat_phdr& phdr) {
    phdr.version = phdr_in.getVersion();
    return 0;
}

static int read_netmon_phdr(NetmonPHdr::Reader phdr_in, netmon_phdr& phdr) {
    phdr.title = const_cast<guint8*>(reinterpret_cast<const guint8*>(phdr_in.getTitle().cStr()));
    phdr.descLength = phdr_in.getDescLength();
    phdr.description =
        const_cast<guint8*>(reinterpret_cast<const guint8*>(phdr_in.getDescription().cStr()));
    phdr.sub_encap = phdr_in.getSubEncap();
    auto subhdr = phdr_in.getSubheader();
    switch (subhdr.which()) {
    case NetmonPHdr::Subheader::ETH:
        return read_eth_phdr(subhdr.getEth(), phdr.subheader.eth);
    case NetmonPHdr::Subheader::ATM:
        return read_atm_phdr(subhdr.getAtm(), phdr.subheader.atm);
    case NetmonPHdr::Subheader::IEEE80211:
        return read_ieee_802_11_phdr(subhdr.getIeee80211(), phdr.subheader.ieee_802_11);
    default:
        return 0;
    }
}

static int read_packet_header(wtap_dumper* wdh, PacketHeader::Reader hdr_in, wtap_rec& rec) {
    int err = 0;
    char* err_msg = nullptr;
    auto& hdr = rec.rec_header.packet_header;
    auto data = hdr_in.getData();
    hdr.caplen = static_cast<guint32>(data.size());
    hdr.len = hdr_in.getLen();
    hdr.pkt_encap = hdr_in.getPktEncap();
    hdr.interface_id = hdr_in.getInterfaceId();
    hdr.drop_count = hdr_in.getDropCount();
    hdr.pack_flags = hdr_in.getPackFlags();
    hdr.interface_queue = hdr_in.getInterfaceQueue();
    hdr.packet_id = hdr_in.getPacketId();

    auto pseudo = hdr_in.getPseudoHeader();
    auto& phdr = hdr.pseudo_header;
    switch (pseudo.which()) {
    case PacketHeader::PseudoHeader::ETH:
        err = read_eth_phdr(pseudo.getEth(), phdr.eth);
        break;
    case PacketHeader::PseudoHeader::DTE_DCE:
        err = read_dte_dce_phdr(pseudo.getDteDce(), phdr.dte_dce);
        break;
    case PacketHeader::PseudoHeader::ISDN:
        err = read_isdn_phdr(pseudo.getIsdn(), phdr.isdn);
        break;
    case PacketHeader::PseudoHeader::ATM:
        err = read_atm_phdr(pseudo.getAtm(), phdr.atm);
        break;
    case PacketHeader::PseudoHeader::ASCEND:
        err = read_ascend_phdr(pseudo.getAscend(), phdr.ascend);
        break;
    case PacketHeader::PseudoHeader::P2P:
        err = read_p2p_phdr(pseudo.getP2p(), phdr.p2p);
        break;
    case PacketHeader::PseudoHeader::IEEE80211:
        err = read_ieee_802_11_phdr(pseudo.getIeee80211(), phdr.ieee_802_11);
        break;
    case PacketHeader::PseudoHeader::COSINE:
        err = read_cosine_phdr(pseudo.getCosine(), phdr.cosine);
        break;
    case PacketHeader::PseudoHeader::IRDA:
        err = read_irda_phdr(pseudo.getIrda(), phdr.irda);
        break;
    case PacketHeader::PseudoHeader::NETTL:
        err = read_nettl_phdr(pseudo.getNettl(), phdr.nettl);
        break;
    case PacketHeader::PseudoHeader::MTP2:
        err = read_mtp2_phdr(pseudo.getMtp2(), phdr.mtp2);
        break;
    case PacketHeader::PseudoHeader::K12:
        err = read_k12_phdr(pseudo.getK12(), phdr.k12);
        break;
    case PacketHeader::PseudoHeader::LAPD:
        err = read_lapd_phdr(pseudo.getLapd(), phdr.lapd);
        break;
    case PacketHeader::PseudoHeader::ERF:
        err = read_erf_mc_phdr(pseudo.getErf(), phdr.erf);
        break;
    case PacketHeader::PseudoHeader::SITA:
        err = read_sita_phdr(pseudo.getSita(), phdr.sita);
        break;
    case PacketHeader::PseudoHeader::BTHCI:
        err = read_bthci_phdr(pseudo.getBthci(), phdr.bthci);
        break;
    case PacketHeader::PseudoHeader::BTMON:
        err = read_btmon_phdr(pseudo.getBtmon(), phdr.btmon);
        break;
    case PacketHeader::PseudoHeader::L1EVENT:
        err = read_l1event_phdr(pseudo.getL1event(), phdr.l1event);
        break;
    case PacketHeader::PseudoHeader::I2C:
        err = read_i2c_phdr(pseudo.getI2c(), phdr.i2c);
        break;
    case PacketHeader::PseudoHeader::GSM_UM:
        err = read_gsm_um_phdr(pseudo.getGsmUm(), phdr.gsm_um);
        break;
    case PacketHeader::PseudoHeader::NSTR:
        err = read_nstr_phdr(pseudo.getNstr(), phdr.nstr);
        break;
    case PacketHeader::PseudoHeader::NOKIA:
        err = read_nokia_phdr(pseudo.getNokia(), phdr.nokia);
        break;
    case PacketHeader::PseudoHeader::LLCP:
        err = read_llcp_phdr(pseudo.getLlcp(), phdr.llcp);
        break;
    case PacketHeader::PseudoHeader::LOGCAT:
        err = read_logcat_phdr(pseudo.getLogcat(), phdr.logcat);
        break;
    case PacketHeader::PseudoHeader::NETMON:
        err = read_netmon_phdr(pseudo.getNetmon(), phdr.netmon);
        break;
    default:
        break;
    }

    if (err == 0 && !wtap_dump(wdh, &rec, data.begin(), &err, &err_msg)) {
        std::cerr << err_msg << '\n';
        g_free(err_msg);
    }
    return err;
}

static int read_syscall_header(wtap_dumper* wdh, SyscallHeader::Reader hdr_in, wtap_rec& rec) {
    int err = 0;
    char* err_msg = nullptr;
    auto& hdr = rec.rec_header.syscall_header;
    auto data = hdr_in.getData();
    hdr.record_type = hdr_in.getRecordType();
    hdr.byte_order = hdr_in.getByteOrder();
    hdr.timestamp = hdr_in.getTimestamp();
    hdr.thread_id = hdr_in.getThreadId();
    hdr.event_len = hdr_in.getEventLen();
    hdr.event_filelen = data.size();
    hdr.event_type = static_cast<guint16>(hdr_in.getEventType());
    hdr.nparams = hdr_in.getNparams();
    if (!wtap_dump(wdh, &rec, data.begin(), &err, &err_msg)) {
        std::cerr << err_msg << '\n';
        g_free(err_msg);
    }
    return err;
}

static int read_systemd_journal_header(wtap_dumper* wdh,
                                       SystemdJournalHeader::Reader hdr_in,
                                       wtap_rec& rec) {
    int err = 0;
    char* err_msg = nullptr;
    auto data = hdr_in.getData();
    rec.rec_header.systemd_journal_header.record_len = static_cast<guint32>(data.size());
    if (!wtap_dump(wdh, &rec, data.begin(), &err, &err_msg)) {
        std::cerr << err_msg << '\n';
        g_free(err_msg);
    }
    return err;
}

static int write_record(wtap_dumper* wdh, Record::Reader rec_in) {
    int err = 0;
    wtap_rec rec{};
    rec.presence_flags = rec_in.getPresenceFlags();
    auto ts = rec_in.getTs();
    rec.ts.secs = ts.getSecs();
    rec.ts.nsecs = ts.getNsecs();
    rec.tsprec = rec_in.getTsprec();
    auto comment = rec_in.getOptComment();
    if (comment.isSome()) {
        rec.opt_comment = const_cast<char*>(comment.getSome().cStr());
    } else {
        rec.opt_comment = nullptr;
    }
    rec.has_comment_changed = rec_in.getHasCommentChanged();
    auto verdict = rec_in.getPacketVerdict();
    if (verdict.isSome()) {
        auto v = verdict.getSome();
        auto arr = g_ptr_array_sized_new(static_cast<guint>(v.size()));
        rec.packet_verdict = arr;
        for (auto ent : v) { g_ptr_array_add(arr, const_cast<uint8_t*>(ent.begin())); }
    } else {
        rec.packet_verdict = nullptr;
    }
    auto opts_buf = rec_in.getOptionsBuf();
    ws_buffer_init(&rec.options_buf, opts_buf.size());
    ws_buffer_append(&rec.options_buf,
                     const_cast<guint8*>(reinterpret_cast<const guint8*>(opts_buf.begin())),
                     opts_buf.size());

    auto hdr = rec_in.getRecHeader();
    switch (hdr.which()) {
    case Record::RecHeader::PACKET_HEADER:
        rec.rec_type = REC_TYPE_PACKET;
        err = read_packet_header(wdh, hdr.getPacketHeader(), rec);
        break;
    case Record::RecHeader::SYSCALL_HEADER:
        rec.rec_type = REC_TYPE_SYSCALL;
        err = read_syscall_header(wdh, hdr.getSyscallHeader(), rec);
        break;
    case Record::RecHeader::SYSTEMD_JOURNAL_HEADER:
        rec.rec_type = REC_TYPE_SYSTEMD_JOURNAL;
        err = read_systemd_journal_header(wdh, hdr.getSystemdJournalHeader(), rec);
        break;
    default:
        std::cerr << "invalid record header\n";
        err = 1;
        break;
    }

    ws_buffer_free(&rec.options_buf);
    if (rec.packet_verdict != nullptr) { g_ptr_array_free(rec.packet_verdict, 1); }
    return err;
}

static int write_iface(wtap_dumper* wdh, IfaceDesc::Reader iface_in) {
    int err = 0;
    char* err_msg = nullptr;
    auto idb = wtap_block_create(WTAP_BLOCK_IF_DESCR);

    auto mand = (wtapng_if_descr_mandatory_t*)wtap_block_get_mandatory_data(idb);
    mand->wtap_encap = iface_in.getEncap();
    mand->time_units_per_second = iface_in.getTimeUnitsPerSecond();
    mand->snap_len = iface_in.getSnapLen();
    switch (iface_in.getTsprecision()) {
    case TSPrec::PER_PACKET:
        mand->tsprecision = WTAP_TSPREC_PER_PACKET;
        break;
    case TSPrec::SEC:
        mand->tsprecision = WTAP_TSPREC_SEC;
        break;
    case TSPrec::DSEC:
        mand->tsprecision = WTAP_TSPREC_DSEC;
        break;
    case TSPrec::CSEC:
        mand->tsprecision = WTAP_TSPREC_CSEC;
        break;
    case TSPrec::MSEC:
        mand->tsprecision = WTAP_TSPREC_MSEC;
        break;
    case TSPrec::USEC:
        mand->tsprecision = WTAP_TSPREC_USEC;
        break;
    case TSPrec::NSEC:
        mand->tsprecision = WTAP_TSPREC_NSEC;
        break;
    default:
        mand->tsprecision = WTAP_TSPREC_UNKNOWN;
        break;
    }

    auto name = iface_in.getName();
    auto desc = iface_in.getDescription();
    auto speed = iface_in.getSpeed();
    auto tsresol = iface_in.getTsresol();
    auto os = iface_in.getOs();
    auto fcslen = iface_in.getFcslen();
    auto hw = iface_in.getHardware();

    if (name.isSome()) {
        auto val = name.getSome();
        auto rc = wtap_block_add_string_option(idb, OPT_IDB_NAME, val.cStr(), val.size() + 1);
        if (rc != WTAP_OPTTYPE_SUCCESS) {
            std::cerr << "failed to set IDB name option\n";
            err = rc;
        }
    }

    if (desc.isSome()) {
        auto val = desc.getSome();
        auto rc = wtap_block_add_string_option(idb, OPT_IDB_DESCR, val.cStr(), val.size() + 1);
        if (rc != WTAP_OPTTYPE_SUCCESS) {
            std::cerr << "failed to set IDB description option\n";
            err = rc;
        }
    }

    if (speed.isSome()) {
        auto val = speed.getSome();
        auto rc = wtap_block_add_uint64_option(idb, OPT_IDB_SPEED, val);
        if (rc != WTAP_OPTTYPE_SUCCESS) {
            std::cerr << "failed to set IDB speed option\n";
            err = rc;
        }
    }

    if (tsresol.isSome()) {
        auto val = tsresol.getSome();
        auto rc = wtap_block_add_uint8_option(idb, OPT_IDB_TSRESOL, val);
        if (rc != WTAP_OPTTYPE_SUCCESS) {
            std::cerr << "failed to set IDB tsresol option\n";
            err = rc;
        }
    }

    if (os.isSome()) {
        auto val = os.getSome();
        auto rc = wtap_block_add_string_option(idb, OPT_IDB_OS, val.cStr(), val.size() + 1);
        if (rc != WTAP_OPTTYPE_SUCCESS) {
            std::cerr << "failed to set IDB os option\n";
            err = rc;
        }
    }

    if (fcslen.isSome()) {
        auto val = fcslen.getSome();
        auto rc = wtap_block_add_uint8_option(idb, OPT_IDB_FCSLEN, val);
        if (rc != WTAP_OPTTYPE_SUCCESS) {
            std::cerr << "failed to set IDB fcslen option\n";
            err = rc;
        }
    }

    if (hw.isSome()) {
        auto val = hw.getSome();
        auto rc = wtap_block_add_string_option(idb, OPT_IDB_HARDWARE, val.cStr(), val.size() + 1);
        if (rc != WTAP_OPTTYPE_SUCCESS) {
            std::cerr << "failed to set IDB hardware option\n";
            err = rc;
        }
    }

    if (!wtap_dump_add_idb(wdh, idb, &err, &err_msg)) {
        std::cerr << err_msg << '\n';
        g_free(err_msg);
    }
    wtap_block_free(idb);
    return err;
}

static int write_ipv4_host(addrinfo_lists_t* nameres, IPv4Host::Reader ipv4_in) {
    if (nameres == nullptr) { return 0; }

    auto addr_in = ipv4_in.getAddr();

    auto ipv4 = new hashipv4;
    ipv4->addr = 0;
    ipv4->addr |= static_cast<guint>(addr_in[0]) << 24;
    ipv4->addr |= static_cast<guint>(addr_in[1]) << 16;
    ipv4->addr |= static_cast<guint>(addr_in[2]) << 8;
    ipv4->addr |= static_cast<guint>(addr_in[3]);
    ipv4->flags = 2;
    if (inet_ntop(AF_INET, &ipv4->addr, ipv4->ip, WS_INET_ADDRSTRLEN) == nullptr) {
        delete ipv4;
        std::cerr << "Failed to convert IPv4 address to string\n";
        return 1;
    }
    std::strcpy(ipv4->name, ipv4_in.getName().cStr());

    nameres->ipv4_addr_list = g_list_append(nameres->ipv4_addr_list, ipv4);

    return 0;
}

static int write_ipv6_host(addrinfo_lists_t* nameres, IPv6Host::Reader ipv6_in) {
    if (nameres == nullptr) { return 0; }

    auto ipv6 = new hashipv6;
    std::memcpy(ipv6->addr, ipv6_in.getAddr().begin(), 16);
    ipv6->flags = 2;
    if (inet_ntop(AF_INET6, ipv6->addr, ipv6->ip6, WS_INET6_ADDRSTRLEN) == nullptr) {
        delete ipv6;
        std::cerr << "Failed to convert IPv6 address to string\n";
        return 1;
    }
    std::strcpy(ipv6->name, ipv6_in.getName().cStr());

    nameres->ipv6_addr_list = g_list_append(nameres->ipv6_addr_list, ipv6);

    return 0;
}

static int write_secrets(GArray* dsbs,
                         std::vector<std::vector<guint8>>& secrets_cache,
                         DecryptSecrets::Reader scrts_in) {
    if (dsbs == nullptr) { return 0; }

    auto dsb = wtap_block_create(WTAP_BLOCK_DSB);
    auto data = reinterpret_cast<wtapng_dsb_mandatory_t*>(wtap_block_get_mandatory_data(dsb));
    data->secrets_type = scrts_in.getType();
    auto secrets = scrts_in.getSecrets();
    auto& scrts_buf = secrets_cache.emplace_back(secrets.begin(), secrets.end());
    data->secrets_len = static_cast<guint32>(scrts_buf.size());
    data->secrets_data = scrts_buf.data();
    g_array_append_val(dsbs, dsb);

    return 0;
}

int write() {
    int err = 0;
    gchar* err_msg = nullptr;

    int filetype = -1;
    wtap_dump_params params{};
    {
        kj::std::StdInputStream in_stream{ std::cin };
        capnp::InputStreamMessageReader message{ in_stream };
        auto info = message.getRoot<CaptureInfo>();
        filetype = static_cast<int>(info.getFiletype());
        params.encap = static_cast<int>(info.getEncap());
        params.snaplen = static_cast<int>(info.getSnaplen());
        switch (info.getTsprec()) {
        default:
        case TSPrec::UNKNOWN:
            params.tsprec = WTAP_TSPREC_UNKNOWN;
            break;
        case TSPrec::PER_PACKET:
            params.tsprec = WTAP_TSPREC_PER_PACKET;
            break;
        case TSPrec::SEC:
            params.tsprec = WTAP_TSPREC_SEC;
            break;
        case TSPrec::DSEC:
            params.tsprec = WTAP_TSPREC_DSEC;
            break;
        case TSPrec::CSEC:
            params.tsprec = WTAP_TSPREC_CSEC;
            break;
        case TSPrec::MSEC:
            params.tsprec = WTAP_TSPREC_MSEC;
            break;
        case TSPrec::USEC:
            params.tsprec = WTAP_TSPREC_USEC;
            break;
        case TSPrec::NSEC:
            params.tsprec = WTAP_TSPREC_NSEC;
            break;
        }
    }

    GArray* dsbs = g_array_new(0, 0, sizeof(wtap_block_t));
    addrinfo_lists_t nameres_s{ nullptr, nullptr };
    addrinfo_lists_t* nameres = &nameres_s;

    params.shb_hdrs = nullptr;
    params.idb_inf = nullptr;
    params.nrb_hdrs = nullptr;
    params.dsbs_initial = nullptr;
    params.dsbs_growing = dsbs;
    params.dont_copy_idbs = 1;

    auto wdh = wtap_dump_open_stdout(filetype, WTAP_UNCOMPRESSED, &params, &err, &err_msg);
    if (wdh == nullptr) {
        std::cerr << err_msg << '\n';
        g_free(err_msg);
        return err;
    }

    if (wtap_dump_set_addrinfo_list(wdh, nameres) == 0) { nameres = nullptr; }

    std::vector<std::vector<guint8>> secrets;

    while (std::cin.peek() != std::char_traits<char>::eof()) {
        kj::std::StdInputStream in_stream{ std::cin };
        capnp::InputStreamMessageReader message{ in_stream };
        auto entry = message.getRoot<CaptureEntry>();
        switch (entry.which()) {
        case CaptureEntry::RECORD:
            err = write_record(wdh, entry.getRecord());
            break;
        case CaptureEntry::IFACE:
            err = write_iface(wdh, entry.getIface());
            break;
        case CaptureEntry::IPV4_HOST:
            err = write_ipv4_host(nameres, entry.getIpv4Host());
            break;
        case CaptureEntry::IPV6_HOST:
            err = write_ipv6_host(nameres, entry.getIpv6Host());
            break;
        case CaptureEntry::SECRETS:
            err = write_secrets(dsbs, secrets, entry.getSecrets());
            break;
        default:
            std::cerr << "malformed CaptureEntry\n";
            return 1;
        }
        if (err != 0) { return err; };
    }

    if (wtap_dump_close(wdh, &err, &err_msg) == 0) {
        std::cerr << err_msg << '\n';
        g_free(err_msg);
    }

    for (guint i = 0; i < dsbs->len; ++i) { wtap_block_free(g_array_index(dsbs, wtap_block_t, i)); }
    g_array_free(dsbs, 1);
    if (nameres_s.ipv4_addr_list) {
        g_list_free_full(nameres_s.ipv4_addr_list, &destroy<hashipv4>);
    }
    if (nameres_s.ipv6_addr_list) {
        g_list_free_full(nameres_s.ipv6_addr_list, &destroy<hashipv6>);
    }

    return err;
}

} // namespace sharkdb
