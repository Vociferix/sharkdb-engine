/* SharkDB backend Wireshark engine.
 * Copyright (C) 2021  Jack Bernard
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "read.hpp"

#include <capnp/message.h>
#include <capnp/serialize.h>
#include <kj/std/iostream.h>
#include <wiretap/wtap.h>

#include <cstring>
#include <iostream>

#include "sharkdb_read.capnp.h"

namespace sharkdb {

static kj::OutputStream* out = nullptr;

static void add_ipv4_name(const guint addr_, const gchar* name_) {
    auto ipv4 = static_cast<uint32_t>(addr_);
    capnp::MallocMessageBuilder message;
    auto entry = message.initRoot<CaptureEntry>();
    auto host = entry.initIpv4Host();
    auto addr = host.initAddr(4);
    std::memcpy(addr.begin(), &ipv4, 4);
    auto name_len = std::strlen(name_);
    auto name = host.initName(name_len);
    std::memcpy(name.begin(), name_, name_len + 1);
    capnp::writeMessage(*out, message);
}

static void add_ipv6_name(const void* addrp, const gchar* name_) {
    capnp::MallocMessageBuilder message;
    auto entry = message.initRoot<CaptureEntry>();
    auto host = entry.initIpv6Host();
    auto addr = host.initAddr(16);
    std::memcpy(addr.begin(), addrp, 16);
    auto name_len = std::strlen(name_);
    auto name = host.initName(name_len);
    std::memcpy(name.begin(), name_, name_len + 1);
    capnp::writeMessage(*out, message);
}

static void add_secrets(guint32 secrets_type, const void* secrets_, guint size) {
    capnp::MallocMessageBuilder message;
    auto entry = message.initRoot<CaptureEntry>();
    auto decrypt_secrets = entry.initSecrets();
    decrypt_secrets.setType(secrets_type);
    auto secrets = decrypt_secrets.initSecrets(size);
    std::memcpy(secrets.begin(), secrets_, size);
    capnp::writeMessage(*out, message);
}

static int write_new_idbs(wtap* wth) {
    wtap_block_t idb = nullptr;
    char* str_val = nullptr;
    guint64 u64_val = 0;
    guint8 u8_val = 0;
    capnp::MallocMessageBuilder message;
    auto entry = message.initRoot<CaptureEntry>();
    auto iface = entry.initIface();
    auto name = iface.initName();
    auto description = iface.initDescription();
    auto speed = iface.initSpeed();
    auto tsresol = iface.initTsresol();
    auto os = iface.initOs();
    auto fcslen = iface.initFcslen();
    auto hardware = iface.initHardware();

    while ((idb = wtap_get_next_interface_description(wth)) != nullptr) {
        if (wtap_block_get_string_option_value(idb, OPT_IDB_NAME, &str_val) ==
            WTAP_OPTTYPE_SUCCESS) {
            name.setSome(str_val);
        } else {
            name.setNone();
        }

        if (wtap_block_get_string_option_value(idb, OPT_IDB_DESCR, &str_val) ==
            WTAP_OPTTYPE_SUCCESS) {
            description.setSome(str_val);
        } else {
            description.setNone();
        }

        if (wtap_block_get_uint64_option_value(idb, OPT_IDB_SPEED, &u64_val) ==
            WTAP_OPTTYPE_SUCCESS) {
            speed.setSome(u64_val);
        } else {
            speed.setNone();
        }

        if (wtap_block_get_uint8_option_value(idb, OPT_IDB_TSRESOL, &u8_val) ==
            WTAP_OPTTYPE_SUCCESS) {
            tsresol.setSome(u8_val);
        } else {
            tsresol.setNone();
        }

        if (wtap_block_get_string_option_value(idb, OPT_IDB_OS, &str_val) == WTAP_OPTTYPE_SUCCESS) {
            os.setSome(str_val);
        } else {
            os.setNone();
        }

        if (wtap_block_get_uint8_option_value(idb, OPT_IDB_FCSLEN, &u8_val) ==
            WTAP_OPTTYPE_SUCCESS) {
            fcslen.setSome(u8_val);
        } else {
            fcslen.setNone();
        }

        if (wtap_block_get_string_option_value(idb, OPT_IDB_HARDWARE, &str_val) ==
            WTAP_OPTTYPE_SUCCESS) {
            hardware.setSome(str_val);
        } else {
            hardware.setNone();
        }

        capnp::writeMessage(*out, message);
    }

    return 0;
}

static int write_eth_phdr(EthPHdr::Builder phdr, eth_phdr* eth) {
    phdr.setFcsLen(eth->fcs_len);
    return 0;
}

static int write_dte_dce_phdr(DteDcePHdr::Builder phdr, dte_dce_phdr* dte_dce) {
    phdr.setFlags(dte_dce->flags);
    return 0;
}

static int write_isdn_phdr(IsdnPHdr::Builder phdr, isdn_phdr* isdn) {
    phdr.setUton(isdn->uton != 0);
    phdr.setChannel(isdn->channel);
    return 0;
}

static int write_atm_phdr(AtmPHdr::Builder phdr, atm_phdr* atm) {
    phdr.setFlags(atm->flags);
    phdr.setAal(atm->aal);
    phdr.setType(atm->type);
    phdr.setSubtype(atm->subtype);
    phdr.setVpi(atm->vpi);
    phdr.setVci(atm->vci);
    phdr.setAal2Cid(atm->aal2_cid);
    phdr.setChannel(atm->channel);
    phdr.setCells(atm->cells);
    phdr.setAal5tU2u(atm->aal5t_u2u);
    phdr.setAal5tLen(atm->aal5t_len);
    phdr.setAal5tChksum(atm->aal5t_chksum);
    return 0;
}

static int write_ascend_phdr(AscendPHdr::Builder phdr, ascend_phdr* ascend) {
    phdr.setType(ascend->type);
    phdr.setUser(ascend->user);
    phdr.setSess(ascend->sess);
    phdr.setCallNum(ascend->call_num);
    phdr.setChunk(ascend->chunk);
    phdr.setTask(ascend->task);
    return 0;
}

static int write_p2p_phdr(P2PPHdr::Builder phdr, p2p_phdr* p2p) {
    phdr.setSent(p2p->sent != 0);
    return 0;
}

static int write_ieee_802_11_fhss(Ieee80211Fhss::Builder hdr, ieee_802_11_fhss* fhss) {
    auto hop_set = hdr.initHopSet();
    auto hop_pattern = hdr.initHopPattern();
    auto hop_index = hdr.initHopIndex();

    if (fhss->has_hop_set) { hop_set.setSome(fhss->hop_set); }

    if (fhss->has_hop_pattern) { hop_pattern.setSome(fhss->hop_pattern); }

    if (fhss->has_hop_index) { hop_index.setSome(fhss->hop_index); }

    return 0;
}

static int write_ieee_802_11b(Ieee80211b::Builder hdr, ieee_802_11b* b) {
    auto short_preamble = hdr.initShortPreamble();
    if (b->has_short_preamble) { short_preamble.setSome(b->short_preamble != 0); }
    return 0;
}

static int write_ieee_802_11a(Ieee80211a::Builder hdr, ieee_802_11a* a) {
    auto channel_type = hdr.initChannelType();
    auto turbo_type = hdr.initTurboType();

    if (a->has_channel_type) { channel_type.setSome(a->channel_type); }

    if (a->has_turbo_type) { turbo_type.setSome(a->turbo_type); }

    return 0;
}

static int write_ieee_802_11g(Ieee80211g::Builder hdr, ieee_802_11g* g) {
    auto short_preamble = hdr.initShortPreamble();
    auto mode = hdr.initMode();

    if (g->has_short_preamble) { short_preamble.setSome(g->short_preamble != 0); }

    if (g->has_mode) { mode.setSome(g->mode); }

    return 0;
}

static int write_ieee_802_11n(Ieee80211n::Builder hdr, ieee_802_11n* n) {
    auto mcs_index = hdr.initMcsIndex();
    auto bandwidth = hdr.initBandwidth();
    auto short_gi = hdr.initShortGi();
    auto greenfield = hdr.initGreenfield();
    auto fec = hdr.initFec();
    auto stbc_streams = hdr.initStbcStreams();
    auto ness = hdr.initNess();

    if (n->has_mcs_index) { mcs_index.setSome(n->mcs_index); }

    if (n->has_bandwidth) { bandwidth.setSome(n->bandwidth); }

    if (n->has_short_gi) { short_gi.setSome(n->short_gi != 0); }

    if (n->has_greenfield) { greenfield.setSome(n->greenfield != 0); }

    if (n->has_fec) { fec.setSome(n->fec != 0); }

    if (n->has_stbc_streams) { stbc_streams.setSome(n->stbc_streams); }

    if (n->has_ness) { ness.setSome(n->ness); }

    return 0;
}

static int write_ieee_802_11ac(Ieee80211ac::Builder hdr, ieee_802_11ac* ac) {
    auto stbc = hdr.initStbc();
    auto txop_ps_not_allowed = hdr.initTxopPsNotAllowed();
    auto short_gi = hdr.initShortGi();
    auto short_gi_nsym_disambig = hdr.initShortGiNsymDisambig();
    auto ldpc_extra_ofdm_symbol = hdr.initLdpcExtraOfdmSymbol();
    auto beamformed = hdr.initBeamformed();
    auto bandwidth = hdr.initBandwidth();
    hdr.setMcs0(ac->mcs[0]);
    hdr.setMcs1(ac->mcs[1]);
    hdr.setMcs2(ac->mcs[2]);
    hdr.setMcs3(ac->mcs[3]);
    hdr.setNss0(ac->nss[0]);
    hdr.setNss1(ac->nss[1]);
    hdr.setNss2(ac->nss[2]);
    hdr.setNss3(ac->nss[3]);
    auto fec = hdr.initFec();
    auto group_id = hdr.initGroupId();
    auto partial_aid = hdr.initPartialAid();

    if (ac->has_stbc) { stbc.setSome(ac->stbc != 0); }

    if (ac->has_txop_ps_not_allowed) { txop_ps_not_allowed.setSome(ac->txop_ps_not_allowed != 0); }

    if (ac->has_short_gi) { short_gi.setSome(ac->short_gi != 0); }

    if (ac->has_short_gi_nsym_disambig) {
        short_gi_nsym_disambig.setSome(ac->short_gi_nsym_disambig != 0);
    }

    if (ac->has_ldpc_extra_ofdm_symbol) {
        ldpc_extra_ofdm_symbol.setSome(ac->ldpc_extra_ofdm_symbol != 0);
    }

    if (ac->has_beamformed) { beamformed.setSome(ac->beamformed != 0); }

    if (ac->has_bandwidth) { bandwidth.setSome(ac->bandwidth); }

    if (ac->has_fec) { fec.setSome(ac->fec); }

    if (ac->has_group_id) { group_id.setSome(ac->group_id); }

    if (ac->has_partial_aid) { partial_aid.setSome(ac->partial_aid); }

    return 0;
}

static int write_ieee_802_11ad(Ieee80211ad::Builder hdr, ieee_802_11ad* ad) {
    auto mcs = hdr.initMcs();
    if (ad->has_mcs_index) { mcs.setSome(ad->mcs); }
    return 0;
}

static int write_ieee_802_11ax(Ieee80211ax::Builder hdr, ieee_802_11ax* ax) {
    hdr.setNsts(ax->nsts);
    auto mcs = hdr.initMcs();
    auto bwru = hdr.initBwru();
    auto gi = hdr.initGi();

    if (ax->has_mcs_index) { mcs.setSome(ax->mcs); }

    if (ax->has_bwru) { bwru.setSome(ax->bwru); }

    if (ax->has_gi) { gi.setSome(ax->gi); }

    return 0;
}

static int write_ieee_802_11_phdr(Ieee80211PHdr::Builder phdr, ieee_802_11_phdr* ieee_802_11) {
    int err = 0;
    phdr.setFcsLen(ieee_802_11->fcs_len);
    phdr.setDecrypted(ieee_802_11->decrypted != 0);
    phdr.setDatapad(ieee_802_11->datapad != 0);
    phdr.setNoAMsdus(ieee_802_11->no_a_msdus != 0);
    phdr.setPhy(ieee_802_11->phy);
    auto phy_info = phdr.initPhyInfo();
    switch (ieee_802_11->phy) {
    case PHDR_802_11_PHY_11_FHSS:
        err =
            write_ieee_802_11_fhss(phy_info.initInfo11fhss(), &ieee_802_11->phy_info.info_11_fhss);
        break;
    case PHDR_802_11_PHY_11B:
        err = write_ieee_802_11b(phy_info.initInfo11b(), &ieee_802_11->phy_info.info_11b);
        break;
    case PHDR_802_11_PHY_11A:
        err = write_ieee_802_11a(phy_info.initInfo11a(), &ieee_802_11->phy_info.info_11a);
        break;
    case PHDR_802_11_PHY_11G:
        err = write_ieee_802_11g(phy_info.initInfo11g(), &ieee_802_11->phy_info.info_11g);
        break;
    case PHDR_802_11_PHY_11N:
        err = write_ieee_802_11n(phy_info.initInfo11n(), &ieee_802_11->phy_info.info_11n);
        break;
    case PHDR_802_11_PHY_11AC:
        err = write_ieee_802_11ac(phy_info.initInfo11ac(), &ieee_802_11->phy_info.info_11ac);
        break;
    case PHDR_802_11_PHY_11AD:
        err = write_ieee_802_11ad(phy_info.initInfo11ad(), &ieee_802_11->phy_info.info_11ad);
        break;
    case PHDR_802_11_PHY_11AX:
        err = write_ieee_802_11ax(phy_info.initInfo11ax(), &ieee_802_11->phy_info.info_11ax);
        break;
    default:
        break;
    }

    auto channel = phdr.initChannel();
    auto frequency = phdr.initFrequency();
    auto data_rate = phdr.initDataRate();
    auto signal_percent = phdr.initSignalPercent();
    auto noise_percent = phdr.initNoisePercent();
    auto signal_dbm = phdr.initSignalDbm();
    auto noise_dbm = phdr.initNoiseDbm();
    auto signal_db = phdr.initSignalDb();
    auto noise_db = phdr.initNoiseDb();
    auto tsf_timestamp = phdr.initTsfTimestamp();
    auto aggregate_info = phdr.initAggregateInfo();
    auto zero_length_psdu_type = phdr.initZeroLengthPsduType();

    if (ieee_802_11->has_channel) { channel.setSome(ieee_802_11->channel); }

    if (ieee_802_11->has_frequency) { frequency.setSome(ieee_802_11->frequency); }

    if (ieee_802_11->has_data_rate) { data_rate.setSome(ieee_802_11->data_rate); }

    if (ieee_802_11->has_signal_percent) { signal_percent.setSome(ieee_802_11->signal_percent); }

    if (ieee_802_11->has_noise_percent) { noise_percent.setSome(ieee_802_11->noise_percent); }

    if (ieee_802_11->has_signal_dbm) { signal_dbm.setSome(ieee_802_11->signal_dbm); }

    if (ieee_802_11->has_noise_dbm) { noise_dbm.setSome(ieee_802_11->noise_dbm); }

    if (ieee_802_11->has_signal_db) { signal_db.setSome(ieee_802_11->signal_db); }

    if (ieee_802_11->has_noise_db) { noise_db.setSome(ieee_802_11->noise_db); }

    if (ieee_802_11->has_tsf_timestamp) { tsf_timestamp.setSome(ieee_802_11->tsf_timestamp); }

    if (ieee_802_11->has_aggregate_info) {
        auto some = aggregate_info.initSome();
        some.setFlags(ieee_802_11->aggregate_flags);
        some.setId(ieee_802_11->aggregate_id);
    }

    if (ieee_802_11->has_zero_length_psdu_type) {
        zero_length_psdu_type.setSome(ieee_802_11->zero_length_psdu_type);
    }

    return err;
}

static int write_cosine_phdr(CosinePHdr::Builder phdr, cosine_phdr* cosine) {
    phdr.setEncap(cosine->encap);
    phdr.setDirection(cosine->direction);
    phdr.setIfName(cosine->if_name);
    phdr.setPro(cosine->pro);
    phdr.setOff(cosine->off);
    phdr.setPri(cosine->pri);
    phdr.setRm(cosine->rm);
    phdr.setErr(cosine->err);
    return 0;
}

static int write_irda_phdr(IrdaPHdr::Builder phdr, irda_phdr* irda) {
    phdr.setPkttype(irda->pkttype);
    return 0;
}

static int write_nettl_phdr(NettlPHdr::Builder phdr, nettl_phdr* nettl) {
    phdr.setSubsys(nettl->subsys);
    phdr.setDevid(nettl->devid);
    phdr.setKind(nettl->kind);
    phdr.setPid(nettl->pid);
    phdr.setUid(nettl->uid);
    return 0;
}

static int write_mtp2_phdr(Mtp2PHdr::Builder phdr, mtp2_phdr* mtp2) {
    phdr.setSent(mtp2->sent);
    phdr.setAnnexAUsed(mtp2->annex_a_used);
    phdr.setLinkNumber(mtp2->link_number);
    return 0;
}

static int write_k12_phdr(K12PHdr::Builder phdr, k12_phdr* k12) {
    phdr.setInput(k12->input);
    phdr.setInputName(k12->input_name);
    phdr.setStackFile(k12->stack_file);
    phdr.setInputType(k12->input_type);
    auto input_info = phdr.initInputInfo();
    if (k12->input_type == K12_PORT_ATMPVC) {
        auto atm = input_info.initAtm();
        atm.setVp(k12->input_info.atm.vp);
        atm.setVc(k12->input_info.atm.vc);
        atm.setCid(k12->input_info.atm.cid);
    }
    auto extra_info = phdr.initExtraInfo(k12->extra_length);
    std::memcpy(extra_info.begin(), k12->extra_info, k12->extra_length);
    return 0;
}

static int write_lapd_phdr(LapdPHdr::Builder phdr, lapd_phdr* lapd) {
    phdr.setPkttype(lapd->pkttype);
    phdr.setWeNetwork(lapd->we_network);
    return 0;
}

static int write_erf_mc_phdr(ErfMcPHdr::Builder phdr, erf_mc_phdr* erf) {
    auto erf_phdr = phdr.initPhdr();
    erf_phdr.setTs(erf->phdr.ts);
    erf_phdr.setType(erf->phdr.type);
    erf_phdr.setFlags(erf->phdr.flags);
    erf_phdr.setRlen(erf->phdr.rlen);
    erf_phdr.setLctr(erf->phdr.lctr);
    erf_phdr.setWlen(erf->phdr.wlen);
    auto ehdr_list = phdr.initEhdrList(MAX_ERF_EHDR);
    for (std::size_t i = 0; i < MAX_ERF_EHDR; ++i) { ehdr_list.set(i, erf->ehdr_list[i].ehdr); }
    phdr.setSubhdr(erf->subhdr.mc_hdr);
    return 0;
}

static int write_sita_phdr(SitaPHdr::Builder phdr, sita_phdr* sita) {
    phdr.setFlags(sita->sita_flags);
    phdr.setSignals(sita->sita_signals);
    phdr.setErrors1(sita->sita_errors1);
    phdr.setErrors2(sita->sita_errors2);
    phdr.setProto(sita->sita_proto);
    return 0;
}

static int write_bthci_phdr(BthciPHdr::Builder phdr, bthci_phdr* bthci) {
    phdr.setSent(bthci->sent != 0);
    phdr.setChannel(bthci->channel);
    return 0;
}

static int write_btmon_phdr(BtmonPHdr::Builder phdr, btmon_phdr* btmon) {
    phdr.setAdapterId(btmon->adapter_id);
    phdr.setOpcode(btmon->opcode);
    return 0;
}

static int write_l1event_phdr(L1EventPHdr::Builder phdr, l1event_phdr* l1event) {
    phdr.setUton(l1event->uton != 0);
    return 0;
}

static int write_i2c_phdr(I2CPHdr::Builder phdr, i2c_phdr* i2c) {
    phdr.setIsEvent(i2c->is_event);
    phdr.setBus(i2c->bus);
    phdr.setFlags(i2c->flags);
    return 0;
}

static int write_gsm_um_phdr(GsmUmPHdr::Builder phdr, gsm_um_phdr* gsm_um) {
    phdr.setUplink(gsm_um->uplink != 0);
    phdr.setChannel(gsm_um->channel);
    phdr.setBsic(gsm_um->bsic);
    phdr.setArfcn(gsm_um->arfcn);
    phdr.setTdmaFrame(gsm_um->tdma_frame);
    phdr.setError(gsm_um->error);
    phdr.setTimeshift(gsm_um->timeshift);
    return 0;
}

static int write_nstr_phdr(NstrPHdr::Builder phdr, nstr_phdr* nstr) {
    phdr.setRecOffset(nstr->rec_offset);
    phdr.setRecLen(nstr->rec_len);
    phdr.setNicnoOffset(nstr->nicno_offset);
    phdr.setNicnoLen(nstr->nicno_len);
    phdr.setDirOffset(nstr->dir_offset);
    phdr.setDirLen(nstr->dir_len);
    phdr.setEthOffset(nstr->eth_offset);
    phdr.setPcbOffset(nstr->pcb_offset);
    phdr.setLPcbOffset(nstr->l_pcb_offset);
    phdr.setRecType(nstr->rec_type);
    phdr.setVlantagOffset(nstr->vlantag_offset);
    phdr.setCoreidOffset(nstr->coreid_offset);
    phdr.setSrcnodeidOffset(nstr->srcnodeid_offset);
    phdr.setDestnodeidOffset(nstr->destnodeid_offset);
    phdr.setClflagsOffset(nstr->clflags_offset);
    phdr.setSrcVmnameLenOffset(nstr->src_vmname_len_offset);
    phdr.setDstVmnameLenOffset(nstr->dst_vmname_len_offset);
    phdr.setNsActivityOffset(nstr->ns_activity_offset);
    phdr.setDataOffset(nstr->data_offset);
    return 0;
}

static int write_llcp_phdr(LlcpPHdr::Builder phdr, llcp_phdr* llcp) {
    phdr.setAdapter(llcp->adapter);
    phdr.setFlags(llcp->flags);
    return 0;
}

static int write_logcat_phdr(LogcatPHdr::Builder phdr, logcat_phdr* logcat) {
    phdr.setVersion(logcat->version);
    return 0;
}

static int write_netmon_phdr(NetmonPHdr::Builder phdr, netmon_phdr* netmon) {
    int err = 0;
    phdr.setTitle(reinterpret_cast<const char*>(netmon->title));
    phdr.setDescLength(netmon->descLength);
    phdr.setDescription(reinterpret_cast<const char*>(netmon->description));
    phdr.setSubEncap(netmon->sub_encap);
    auto subheader = phdr.initSubheader();
    switch (netmon->sub_encap) {
    case WTAP_ENCAP_ETHERNET:
    case WTAP_ENCAP_NETANALYZER:
        err = write_eth_phdr(subheader.initEth(), &netmon->subheader.eth);
        break;
    case WTAP_ENCAP_ATM_PDUS_UNTRUNCATED:
    case WTAP_ENCAP_ATM_PDUS:
        err = write_atm_phdr(subheader.initAtm(), &netmon->subheader.atm);
        break;
    case WTAP_ENCAP_IEEE_802_11:
    case WTAP_ENCAP_IEEE_802_11_PRISM:
    case WTAP_ENCAP_IEEE_802_11_RADIOTAP:
    case WTAP_ENCAP_IEEE_802_11_AVS:
    case WTAP_ENCAP_IEEE_802_11_NETMON:
    case WTAP_ENCAP_IEEE_802_11_WITH_RADIO:
        err = write_ieee_802_11_phdr(subheader.initIeee80211(), &netmon->subheader.ieee_802_11);
        break;
    default:
        break;
    }
    return err;
}

/*
static int write_catapult_dct2000_phdr(PacketHeader::PseudoHeader::Builder phdr,
                                       catapult_dct2000_phdr* dct2000) {
    // TODO
    return 0;
}
*/

static int write_nokia_phdr(NokiaPHdr::Builder phdr, nokia_phdr* nokia) {
    auto err = write_eth_phdr(phdr.initEth(), &nokia->eth);
    if (err != 0) { return err; }
    phdr.setStuff0(nokia->stuff[0]);
    phdr.setStuff1(nokia->stuff[1]);
    phdr.setStuff2(nokia->stuff[2]);
    phdr.setStuff3(nokia->stuff[3]);
    return 0;
}

static int write_packet_record(wtap* wth, wtap_rec* rec, Buffer* buf, Record::Builder record) {
    int err = 0;
    auto rec_header = record.initRecHeader();
    auto header = rec_header.initPacketHeader();
    header.setLen(rec->rec_header.packet_header.len);
    header.setPktEncap(rec->rec_header.packet_header.pkt_encap);
    header.setInterfaceId(rec->rec_header.packet_header.interface_id);
    header.setDropCount(rec->rec_header.packet_header.drop_count);
    header.setPackFlags(rec->rec_header.packet_header.pack_flags);
    header.setInterfaceQueue(rec->rec_header.packet_header.interface_queue);
    header.setPacketId(rec->rec_header.packet_header.packet_id);
    auto pseudo = header.initPseudoHeader();
    auto phdr = &rec->rec_header.packet_header.pseudo_header;
    switch (rec->rec_header.packet_header.pkt_encap) {
    case WTAP_ENCAP_ETHERNET:
        if (wtap_file_type_subtype(wth) == WTAP_FILE_TYPE_SUBTYPE_PCAP_NOKIA) {
            err = write_nokia_phdr(pseudo.initNokia(), &phdr->nokia);
            break;
        }
        [[fallthrough]];

    case WTAP_ENCAP_NETANALYZER:
        err = write_eth_phdr(pseudo.initEth(), &phdr->eth);
        break;

    case WTAP_ENCAP_LAPB:
    case WTAP_ENCAP_FRELAY_WITH_PHDR:
        err = write_dte_dce_phdr(pseudo.initDteDce(), &phdr->dte_dce);
        break;

    case WTAP_ENCAP_ISDN:
        err = write_isdn_phdr(pseudo.initIsdn(), &phdr->isdn);
        break;

    case WTAP_ENCAP_ATM_PDUS_UNTRUNCATED:
    case WTAP_ENCAP_ATM_PDUS:
        err = write_atm_phdr(pseudo.initAtm(), &phdr->atm);
        break;

    case WTAP_ENCAP_ASCEND:
        err = write_ascend_phdr(pseudo.initAscend(), &phdr->ascend);
        break;

    case WTAP_ENCAP_PPP_WITH_PHDR:
    case WTAP_ENCAP_SDLC:
    case WTAP_ENCAP_CHDLC_WITH_PHDR:
    case WTAP_ENCAP_BLUETOOTH_H4_WITH_PHDR:
        err = write_p2p_phdr(pseudo.initP2p(), &phdr->p2p);
        break;

    case WTAP_ENCAP_IEEE_802_11:
    case WTAP_ENCAP_IEEE_802_11_PRISM:
    case WTAP_ENCAP_IEEE_802_11_RADIOTAP:
    case WTAP_ENCAP_IEEE_802_11_AVS:
    case WTAP_ENCAP_IEEE_802_11_NETMON:
    case WTAP_ENCAP_IEEE_802_11_WITH_RADIO:
        err = write_ieee_802_11_phdr(pseudo.initIeee80211(), &phdr->ieee_802_11);
        break;

    case WTAP_ENCAP_COSINE:
        err = write_cosine_phdr(pseudo.initCosine(), &phdr->cosine);
        break;

    case WTAP_ENCAP_IRDA:
        err = write_irda_phdr(pseudo.initIrda(), &phdr->irda);
        break;

    case WTAP_ENCAP_NETTL_FDDI:
    case WTAP_ENCAP_NETTL_ETHERNET:
    case WTAP_ENCAP_NETTL_TOKEN_RING:
    case WTAP_ENCAP_NETTL_RAW_IP:
    case WTAP_ENCAP_NETTL_RAW_ICMP:
    case WTAP_ENCAP_NETTL_RAW_ICMPV6:
    case WTAP_ENCAP_NETTL_RAW_TELNET:
    case WTAP_ENCAP_NETTL_UNKNOWN:
        err = write_nettl_phdr(pseudo.initNettl(), &phdr->nettl);
        break;

    case WTAP_ENCAP_MTP2_WITH_PHDR:
        err = write_mtp2_phdr(pseudo.initMtp2(), &phdr->mtp2);
        break;

    case WTAP_ENCAP_K12:
        err = write_k12_phdr(pseudo.initK12(), &phdr->k12);
        break;

    case WTAP_ENCAP_LINUX_LAPD:
        err = write_lapd_phdr(pseudo.initLapd(), &phdr->lapd);
        break;

        /*
        case WTAP_ENCAP_CATAPULT_DCT2000:
            err = write_catapult_dct2000_phdr(pseudo, &phdr->dct2000);
            break;
        */

    case WTAP_ENCAP_ERF:
        err = write_erf_mc_phdr(pseudo.initErf(), &phdr->erf);
        break;

    case WTAP_ENCAP_SITA:
        err = write_sita_phdr(pseudo.initSita(), &phdr->sita);
        break;

    case WTAP_ENCAP_BLUETOOTH_HCI:
        err = write_bthci_phdr(pseudo.initBthci(), &phdr->bthci);
        break;

    case WTAP_ENCAP_BLUETOOTH_LINUX_MONITOR:
        err = write_btmon_phdr(pseudo.initBtmon(), &phdr->btmon);
        break;

    case WTAP_ENCAP_LAYER1_EVENT:
        err = write_l1event_phdr(pseudo.initL1event(), &phdr->l1event);
        break;

    case WTAP_ENCAP_I2C_LINUX:
        err = write_i2c_phdr(pseudo.initI2c(), &phdr->i2c);
        break;

    case WTAP_ENCAP_GSM_UM:
        err = write_gsm_um_phdr(pseudo.initGsmUm(), &phdr->gsm_um);
        break;

    case WTAP_ENCAP_NSTRACE_1_0:
    case WTAP_ENCAP_NSTRACE_2_0:
    case WTAP_ENCAP_NSTRACE_3_0:
    case WTAP_ENCAP_NSTRACE_3_5:
        err = write_nstr_phdr(pseudo.initNstr(), &phdr->nstr);
        break;

    case WTAP_ENCAP_NFC_LLCP:
        err = write_llcp_phdr(pseudo.initLlcp(), &phdr->llcp);
        break;

    case WTAP_ENCAP_LOGCAT:
        err = write_logcat_phdr(pseudo.initLogcat(), &phdr->logcat);
        break;

    case WTAP_ENCAP_NETMON_HEADER:
        err = write_netmon_phdr(pseudo.initNetmon(), &phdr->netmon);
        break;

    default:
        break;
    }
    if (err != 0) { return err; }
    auto sz = rec->rec_header.packet_header.caplen;
    auto data = header.initData(sz);
    std::memcpy(data.begin(), buf->data + buf->start, sz);
    return 0;
}

static int write_syscall_record(wtap* wth, wtap_rec* rec, Buffer* buf, Record::Builder record) {
    auto rec_header = record.initRecHeader();
    auto header = rec_header.initSyscallHeader();
    header.setRecordType(rec->rec_header.syscall_header.record_type);
    header.setByteOrder(rec->rec_header.syscall_header.byte_order);
    header.setTimestamp(rec->rec_header.syscall_header.timestamp);
    header.setThreadId(rec->rec_header.syscall_header.thread_id);
    header.setEventLen(rec->rec_header.syscall_header.event_len);
    header.setEventType(rec->rec_header.syscall_header.event_type);
    header.setNparams(rec->rec_header.syscall_header.nparams);
    header.setCpuId(rec->rec_header.syscall_header.cpu_id);
    auto sz = rec->rec_header.syscall_header.event_filelen;
    auto data = header.initData(sz);
    std::memcpy(data.begin(), buf->data + buf->start, sz);
    return 0;
}

static int write_systemd_journal_record(wtap* wth,
                                        wtap_rec* rec,
                                        Buffer* buf,
                                        Record::Builder record) {
    auto rec_header = record.initRecHeader();
    auto header = rec_header.initSystemdJournalHeader();
    auto sz = rec->rec_header.systemd_journal_header.record_len;
    auto data = header.initData(sz);
    std::memcpy(data.begin(), buf->data + buf->start, sz);
    return 0;
}

static int write_record(wtap* wth, wtap_rec* rec, Buffer* buf) {
    if (rec->rec_type == REC_TYPE_FT_SPECIFIC_EVENT ||
        rec->rec_type == REC_TYPE_FT_SPECIFIC_REPORT) {
        return 0;
    }

    int err = 0;
    capnp::MallocMessageBuilder message;
    auto entry = message.initRoot<CaptureEntry>();
    auto record = entry.initRecord();
    record.setPresenceFlags(rec->presence_flags);
    auto ts = record.initTs();
    ts.setSecs(rec->ts.secs);
    ts.setNsecs(rec->ts.nsecs);
    record.setTsprec(rec->tsprec);
    switch (rec->rec_type) {
    case REC_TYPE_PACKET:
        err = write_packet_record(wth, rec, buf, record);
        if (err != 0) { return err; }
        break;
    case REC_TYPE_SYSCALL:
        err = write_syscall_record(wth, rec, buf, record);
        if (err != 0) { return err; }
        break;
    case REC_TYPE_SYSTEMD_JOURNAL:
        err = write_systemd_journal_record(wth, rec, buf, record);
        if (err != 0) { return err; }
        break;
    default:
        return 2;
    }
    auto opt_comment = record.initOptComment();
    if (rec->opt_comment != nullptr) { opt_comment.setSome(rec->opt_comment); }
    record.setHasCommentChanged(rec->has_comment_changed != 0);
    auto verdicts_opt = record.initPacketVerdict();
    if (rec->packet_verdict != nullptr) {
        auto verdicts = verdicts_opt.initSome(rec->packet_verdict->len);
        for (guint i = 0; i < rec->packet_verdict->len; ++i) {
            auto bytes = reinterpret_cast<GBytes*>(g_ptr_array_index(rec->packet_verdict, i));
            gsize sz = 0;
            auto data = g_bytes_get_data(bytes, &sz);
            auto verdict = verdicts.init(i, sz);
            std::memcpy(verdict.begin(), data, sz);
        }
    }
    auto options_buf_len = rec->options_buf.first_free - rec->options_buf.start;
    auto options_buf = record.initOptionsBuf(options_buf_len);
    std::memcpy(options_buf.begin(), rec->options_buf.data + rec->options_buf.start,
                options_buf_len);
    capnp::writeMessage(*out, message);

    return 0;
}

int read() {
    int err = 0;
    gchar* err_info = nullptr;
    Buffer buf;
    wtap_rec rec;
    gint64 data_offset = 0;
    kj::std::StdOutputStream out_stream{ std::cout };

    out = &out_stream;

    auto wth = wtap_open_offline("-", WTAP_TYPE_AUTO, &err, &err_info, 0);
    if (wth == nullptr) {
        std::cerr << err_info << '\n';
        return err;
    }
    wtap_set_cb_new_ipv4(wth, add_ipv4_name);
    wtap_set_cb_new_ipv6(wth, add_ipv6_name);
    wtap_set_cb_new_secrets(wth, add_secrets);

    wtap_rec_init(&rec);
    ws_buffer_init(&buf, 1514);
    for (;;) {
        wtap_cleareof(wth);
        auto ret = wtap_read(wth, &rec, &buf, &err, &err_info, &data_offset);
        if (ret == 0) {
            if (err != 0) { std::cerr << err_info << '\n'; }
            break;
        }

        err = write_new_idbs(wth);
        if (err != 0) { break; }

        err = write_record(wth, &rec, &buf);
        if (err != 0) { break; }
    }
    wtap_rec_cleanup(&rec);
    ws_buffer_free(&buf);

    wtap_close(wth);
    out = nullptr;

    return err;
}

} // namespace sharkdb
