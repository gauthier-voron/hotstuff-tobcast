#include <stdio.h>

#include <exception>
#include <list>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <tuple>
#include <vector>

#include "hotstuff/hotstuff.h"
#include "hotstuff/liveness.h"
#include "hotstuff/util.h"

#include "salticidae/crypto.h"
#include "salticidae/util.h"


#define PACEMAKER_PARENT_LIMIT        1
#define PACEMAKER_BASE_TIMEOUT        1
#define PACEMAKER_PROP_DELAY          1

#define REPLICA_MAX_MSGLEN      1048576
#define REPLICA_REPLY_BURST           1
#define REPLICA_WORKERS               1


using hotstuff::from_hex;
using hotstuff::get_hex;
using hotstuff::pacemaker_bt;
using hotstuff::privkey_bt;
using hotstuff::pubkey_bt;
using hotstuff::tls_pkey_bt;
using hotstuff::tls_x509_bt;
using hotstuff::DataStream;
using hotstuff::EventContext;
using hotstuff::Finality;
using hotstuff::NetAddr;
using hotstuff::PaceMakerRR;
using hotstuff::PrivKeySecp256k1;
using hotstuff::ReplicaID;

using salticidae::_1;
using salticidae::_2;
using salticidae::generic_bind;
using salticidae::get_hash;
using salticidae::split;
using salticidae::BoxObj;
using salticidae::ClientNetwork;
using salticidae::ConnPool;

using std::forward_as_tuple;
using std::list;
using std::make_tuple;
using std::map;
using std::move;
using std::nullopt;
using std::optional;
using std::pair;
using std::piecewise_construct;
using std::runtime_error;
using std::set;
using std::stoi;
using std::string;
using std::tuple;
using std::vector;

using tlsPkey = salticidae::PKey;
using tlsX509 = salticidae::X509;
using HotStuff = hotstuff::HotStuffSecp256k1;
using ClientNet = ClientNetwork<uint8_t>;


struct MsgPayload {
    static constexpr uint8_t opcode = 100;

    DataStream serialized;
    bytearray_t payload;

    MsgPayload(const bytearray_t &cmd) {
        serialized.put_data(cmd);
    }

    MsgPayload(DataStream &&s) {
        payload.resize(s.size());
        memcpy(payload.data(), s.get_data_inplace(payload.size()),
               payload.size());
    }
};


class Replica: public HotStuff {
    using conn_t = ClientNet::conn_t;


    struct NetAddrCmp {
        bool operator()(const NetAddr &a, const NetAddr &b) const {
            if (a.ip == b.ip)
                return (a.port < b.port);
            return (a.ip < b.ip);
        }
    };


    ClientNet cn;
    set<NetAddr, NetAddrCmp> clients;


 public:
        Replica(ReplicaID id, size_t blksize, const NetAddr &listen,
                pacemaker_bt pmaker, const bytearray_t &privkey,
                const EventContext &ec, Net::Config &config,
                const NetAddr &clisten) :
        HotStuff(blksize, id, privkey, listen,
               move(pmaker), ec, REPLICA_WORKERS, config),
        cn(ec, ClientNet::Config()) {
        cn.reg_conn_handler(generic_bind(&Replica::on_co, this,_1,_2));
        cn.reg_handler(generic_bind(&Replica::on_cli, this, _1, _2));
        cn.start();
        cn.listen(clisten);
    }

    void state_machine_execute(const Finality &fin) override {
        for (auto it = clients.begin(); it != clients.end();) {
            const auto &client = *it;

            try {
                if (fin.cmd.size() >= 8) {
                    HOTSTUFF_LOG_DEBUG("reply client %lu bytes to %s: %02hhx "
				       "%02hhx %02hhx %02hhx %02hhx %02hhx "
				       "%02hhx %02hhx", fin.cmd.size(),
				       string(client).c_str(), fin.cmd[0],
				       fin.cmd[1], fin.cmd[2], fin.cmd[3],
				       fin.cmd[4], fin.cmd[5], fin.cmd[6],
				       fin.cmd[7]);
		} else {
                    HOTSTUFF_LOG_DEBUG("reply client %lu bytes to %s",
				       fin.cmd.size(), string(client).c_str());
		}
                cn.send_msg(MsgPayload(fin.cmd), client);
                ++it;
            } catch (...) {
                HOTSTUFF_LOG_DEBUG("client %s disconnected",
                           string(client).c_str());
                it = clients.erase(it);
            }
        }
    }

    bool on_co(const ConnPool::conn_t &conn, bool connected) {
        if (connected) {
            clients.insert(conn->get_addr());
            HOTSTUFF_LOG_DEBUG("accepted client %s",
                       string(conn->get_addr()).c_str());
        }

        return true;
    }

    void on_cli(MsgPayload &&msg, const conn_t &c) {
        if (msg.payload.size() >= 8) {
            HOTSTUFF_LOG_DEBUG("received client command (%lu bytes): "
			       "%02hhx %02hhx %02hhx %02hhx %02hhx %02hhx "
			       "%02hhx %02hhx", msg.payload.size(),
			       msg.payload[0], msg.payload[1],
			       msg.payload[2], msg.payload[3],
			       msg.payload[4], msg.payload[5],
			       msg.payload[6], msg.payload[7]);
	} else {
            HOTSTUFF_LOG_DEBUG("received client command (%lu bytes)",
			       msg.payload.size());
	}

        exec_command(msg.payload, [this, msg, c](Finality fin) {
            if (!fin.decision)
                HOTSTUFF_LOG_ERROR("command aborted");
        });
    }
};


static void store_bytearray(FILE *stream, const bytearray_t &arr) {
    uint16_t len = htobe16(arr.size());

    if (!fwrite(&len, sizeof (len), 1, stream) ||
        !fwrite(arr.data(), arr.size(), 1, stream))
        throw runtime_error("");
}

static void load_bytearray(FILE *stream, bytearray_t *arr) {
    uint16_t len;

    if (!fread(&len, sizeof (len), 1, stream))
        throw runtime_error("");
    len = be16toh(len);

    arr->resize(len);
    if (!fread(arr->data(), len, 1, stream))
        throw runtime_error("");
}

struct HotStuffIdentity {
    bytearray_t votekey;
    bytearray_t tlskey;

    void store(const char *path) const {
        FILE *fh = fopen(path, "w");

        if (fh == NULL)
            throw runtime_error(path);

        store_bytearray(fh, votekey);
        store_bytearray(fh, tlskey);

        fclose(fh);
    }

    void load(const char *path) {
        FILE *fh = fopen(path, "r");

        if (fh == NULL)
            throw runtime_error(path);

        load_bytearray(fh, &votekey);
        load_bytearray(fh, &tlskey);

        fclose(fh);
    }
};

template<typename Source, typename Target>
static void copy_rawkey(const Source &source, Target *target) {
    *target = from_hex(get_hex(source));
}

static void generate_votekeys(bytearray_t *privkeydest,bytearray_t*pubkeydest){
    privkey_bt privkey = new PrivKeySecp256k1();
    pubkey_bt pubkey;

    privkey->from_rand();

    if (privkeydest != nullptr)
        copy_rawkey(*privkey, privkeydest);

    if (pubkeydest != nullptr) {
        pubkey = privkey->get_pubkey();
        copy_rawkey(*pubkey, pubkeydest);
    }
}

static void generate_tls(bytearray_t *privkeydest, bytearray_t *pubkeydest) {
    tls_pkey_bt privkey;
    tls_x509_bt pubkey;

    privkey = new tlsPkey(tlsPkey::create_privkey_rsa());

    if (privkeydest != nullptr)
        *privkeydest = privkey->get_privkey_der();

    if (pubkeydest != nullptr) {
        pubkey = new tlsX509(tlsX509::create_self_signed_from_pubkey
                     (*privkey));
        *pubkeydest = pubkey->get_der();
    }
}

static int main_generate(const char *arg) {
    vector<string> paths = split(arg, ":");
    HotStuffIdentity privid, pubid;

    HOTSTUFF_LOG_INFO("generating new keys in '%s'", arg);

    if (paths.size() != 2) {
        HOTSTUFF_LOG_ERROR("invalid key destination format (must be "
                   "'<private-path>:<public-path>')");
        return 1;
    }

    HOTSTUFF_LOG_INFO("generating hotstuff voting keys...");
    generate_votekeys(&privid.votekey, &pubid.votekey);

    HOTSTUFF_LOG_INFO("generating tls keys...");
    generate_tls(&privid.tlskey, &pubid.tlskey);

    HOTSTUFF_LOG_INFO("storing private keys in '%s'", paths[0].c_str());
    privid.store(paths[0].c_str());

    HOTSTUFF_LOG_INFO("storing public keys in '%s'", paths[1].c_str());
    pubid.store(paths[1].c_str());

    return 0;
}

static int run(int id, size_t blksize, const NetAddr &clients,
               const HotStuffIdentity &privid,
               const vector<pair<NetAddr, HotStuffIdentity>> &peers) {
    vector<tuple<NetAddr, bytearray_t, bytearray_t>> peerids;
    Replica::Net::Config rconfig;
    BoxObj<Replica> replica;
    pacemaker_bt pmaker;
    EventContext ec;
    NetAddr raddr;

    for (const auto &peer : peers)
        peerids.push_back(make_tuple(peer.first, peer.second.votekey,
                         get_hash(peer.second.tlskey)));

    pmaker = new PaceMakerRR(ec, PACEMAKER_PARENT_LIMIT,
                 PACEMAKER_BASE_TIMEOUT, PACEMAKER_PROP_DELAY);

    rconfig.max_msg_size(REPLICA_MAX_MSGLEN)
        .burst_size(REPLICA_REPLY_BURST)
        .nworker(REPLICA_WORKERS)
        .enable_tls(true)
        .tls_key(new tlsPkey(tlsPkey::create_privkey_from_der
                     (privid.tlskey)))
        .tls_cert(new tlsX509(tlsX509::create_from_der
                      (peers[id].second.tlskey)));

    replica = new Replica(id, blksize, peers[id].first, move(pmaker),
                          privid.votekey, ec, rconfig, clients);

    replica->start(peerids);

    ec.dispatch();

    return 0;
}

// ./main <id> <client-port>:<private-key>
//        <replica-ip>:<consensus-port>:<public-key>...
static int main_run(int argc, const char **argv) {
    vector<pair<NetAddr, HotStuffIdentity>> peers;
    vector<string> splitted;
    HotStuffIdentity privid;
    int i, id, cport, rport;
    size_t blksize;
    NetAddr caddr;

    try {
        id = stoi(argv[1]);
        HOTSTUFF_LOG_INFO("run replica with id %d", id);
    } catch (...) {
        HOTSTUFF_LOG_ERROR("invalid replica id '%s' (must be uint)",
                   argv[1]);
        return 1;
    }

    try {
        blksize = stoi(argv[2]);
        HOTSTUFF_LOG_INFO("run replica with blksize %lu", blksize);
    } catch (...) {
        HOTSTUFF_LOG_ERROR("invalid blksize '%s' (must be ulong)",
                   argv[2]);
        return 1;
    }

    splitted = split(argv[3], ":");

    if (splitted.size() != 2) {
        HOTSTUFF_LOG_ERROR("invalid replica local info '%s' (must be "
                   "'<client-port>:<private-path>')", argv[3]);
        return 1;
    }

    try {
        cport = stoi(splitted[0]);
    } catch (...) {
        HOTSTUFF_LOG_ERROR("invalid client port '%s' (must be uint)",
                   splitted[0].c_str());
        return 1;
    }

    if ((cport == 0) || (cport > 65535)) {
        HOTSTUFF_LOG_ERROR("invalid client port %d (must be "
                   "uint in [1;65535])", cport);
        return 1;
    }

    caddr = NetAddr("0.0.0.0", cport);

    HOTSTUFF_LOG_INFO("listen clients on %s", string(caddr).c_str());

    try {
        privid.load(splitted[1].c_str());
    } catch (...) {
        HOTSTUFF_LOG_ERROR("failed to load private id from '%s'",
                   splitted[1].c_str());
        return 1;
    }

    HOTSTUFF_LOG_INFO("loaded private identity from '%s'",
              splitted[1].c_str());

    for (i = 4; i < argc; i++) {
        splitted = split(argv[i], ":");

        if (splitted.size() != 3) {
            HOTSTUFF_LOG_ERROR("invalid replica remote info '%s' "
                       "(must be '<host>:<port>:"
                       "<public-path>')", argv[i]);
            return 1;
        }

        try {
            rport = stoi(splitted[1]);
        } catch (...) {
            HOTSTUFF_LOG_ERROR("invalid replica port '%s' (must "
                       "be uint)", splitted[1].c_str());
            return 1;
        }

        if ((rport == 0) || (rport > 65535)) {
            HOTSTUFF_LOG_ERROR("invalid replica port %d (must be "
                       "uint in [1;65535])", rport);
            return 1;
        }

        peers.emplace_back(piecewise_construct,
                   forward_as_tuple(splitted[0], rport),
                   forward_as_tuple());

        HOTSTUFF_LOG_INFO("replica %d has public address %s", (i - 3),
                  string(peers.back().first).c_str());

        try {
            peers.back().second.load(splitted[2].c_str());
        } catch (...) {
            HOTSTUFF_LOG_ERROR("failed to load public id from "
                       "'%s'", splitted[2].c_str());
            return 1;
        }

        HOTSTUFF_LOG_INFO("loaded public identity from '%s' for "
                  "replica %d", splitted[2].c_str(), (i - 3));
    }

    return run(id, blksize, caddr, privid, peers);
}

int main(int argc, const char **argv) {
    if ((argc == 1) || ((argc > 2) && (argc < 4)) ) {
        HOTSTUFF_LOG_ERROR("Syntax error ; see source file for usage");
        return 1;
    }

    if (argc == 2) {
        return main_generate(argv[1]);
    }

    return main_run(argc, argv);
}
