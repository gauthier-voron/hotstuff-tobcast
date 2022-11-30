/**
 * Copyright 2018 VMware
 * Copyright 2018 Ted Yin
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <cassert>
#include <random>
#include <memory>
#include <signal.h>
#include <sys/time.h>

#include "salticidae/type.h"
#include "salticidae/netaddr.h"
#include "salticidae/network.h"
#include "salticidae/util.h"

#include "hotstuff/util.h"
#include "hotstuff/type.h"
#include "hotstuff/client.h"

#define MAX_TICK_HZ  1000
#define SECOND_NS    1000000000ul

using salticidae::Config;
using salticidae::TimerEvent;
using salticidae::_1;

using hotstuff::Command;
using hotstuff::DataStream;
using hotstuff::ReplicaID;
using hotstuff::NetAddr;
using hotstuff::EventContext;
using hotstuff::MsgReqCmd;
using hotstuff::MsgRespCmd;
using hotstuff::HotStuffError;
using hotstuff::uint256_t;
using hotstuff::opcode_t;
using hotstuff::command_t;

EventContext ec;
size_t max_async_num;
uint32_t cid;
uint32_t nfaulty;
size_t cmd_size;
size_t tps = 0;
double tick_sleep;

struct CommandBenchmark : public Command {
    bytearray_t payload;
    uint256_t hash;

    CommandBenchmark(uint32_t cid, uint64_t seq, size_t len)
        : payload(sizeof (cid) + sizeof (seq)) {
        *((uint32_t *) payload.data()) = cid;
        *((uint64_t *) (payload.data() + sizeof (uint32_t))) = seq;
        payload.resize(len);
        hash = salticidae::get_hash(*this);
    }

    CommandBenchmark(DataStream &&s) {
        payload.resize(s.size());
        memcpy(payload.data(), s.get_data_inplace(payload.size()),
               payload.size());
    }

    void serialize(DataStream &s) const override {
        s.put_data(payload);
    }

    void unserialize(DataStream &s) override {
        payload.resize(s.size());
        memcpy(payload.data(), s.get_data_inplace(payload.size()),
               payload.size());
        hash = salticidae::get_hash(*this);
    }

    const uint256_t &get_hash() const override {
        return hash;
    }

    bool verify() const override {
        return true;
    }
};

struct Request {
    command_t cmd;
    size_t confirmed;
    salticidae::ElapsedTime et;
    Request(const command_t &cmd): cmd(cmd), confirmed(0) { et.start(); }
};


using Net = salticidae::MsgNetwork<opcode_t>;

std::unordered_map<ReplicaID, Net::conn_t> conns;
std::unordered_map<const uint256_t, Request> waiting;
std::vector<NetAddr> replicas;
std::vector<std::pair<struct timeval, double>> elapsed;
std::unique_ptr<Net> mn;

TimerEvent ticker;
uint64_t send_start_ns;
size_t sent;
uint64_t sequence = 0;
bool async_wait = false;


static uint64_t now_ns() {
    struct timespec ts;

    ::clock_gettime(CLOCK_REALTIME, &ts);

    return ts.tv_sec * SECOND_NS + ts.tv_nsec;
}

void connect_all() {
    for (size_t i = 0; i < replicas.size(); i++)
        conns.insert(std::make_pair(i, mn->connect_sync(replicas[i])));
}

static void send_request() {
    auto cmd = new CommandBenchmark(cid, sequence++, cmd_size);
    MsgReqCmd msg(*cmd);

    for (auto &p: conns) {
        mn->send_msg(msg, p.second);
    }

    waiting.insert(std::make_pair(cmd->get_hash(), Request(cmd)));
    sent += 1;
}

static void start_send() {
    size_t i;

    if (tps > 0) {
        sent = 0;
        send_start_ns = now_ns();
    } else if (max_async_num > 0) {
        for (i = 0; i < max_async_num; i++)
            send_request();
    } else {
        while (1)
            send_request();
    }
}

static void tick_cb(TimerEvent &) {
    size_t allowed, clearance, i;
    size_t elapsed_ns;
    uint64_t now;

    if ((max_async_num > 0) && (waiting.size() >= max_async_num)) {
        async_wait = true;
        return;
    }

    now = now_ns();
    elapsed_ns = now - send_start_ns;
    allowed = (elapsed_ns * tps) / SECOND_NS;

    if (allowed <= sent)
        goto end;  // caused by rounding

    clearance = allowed - sent;

    for (i = 0; i < clearance; i++)
        send_request();

 end:
    ticker.add(tick_sleep);
}

void client_resp_cmd_handler(MsgRespCmd &&msg, const Net::conn_t &) {
    auto &fin = msg.fin;
    HOTSTUFF_LOG_DEBUG("got %s", std::string(msg.fin).c_str());
    const uint256_t &cmd_hash = salticidae::get_hash(fin.cmd);
    auto it = waiting.find(cmd_hash);
    auto &et = it->second.et;
    bool was_stuck;
    size_t i;

    if (it == waiting.end()) return;
    if (++it->second.confirmed <= nfaulty) return; // wait for f + 1 ack
    et.stop();
    HOTSTUFF_LOG_INFO("got %s, wall: %.3f, cpu: %.3f",
                        std::string(fin).c_str(),
                        et.elapsed_sec, et.cpu_elapsed_sec);

    was_stuck = ((max_async_num > 0) && (waiting.size() >= max_async_num));
    waiting.erase(it);

    if (was_stuck == false)
        return;

    if (waiting.size() >= max_async_num)
        return;

    if ((tps > 0) && async_wait) {
        sent = 0;
        send_start_ns = now_ns();
        ticker.add(tick_sleep);
    } else {
        for (i = 0; i < max_async_num; i++)
            send_request();
    }
}

std::pair<std::string, std::string> split_ip_port_cport(const std::string &s) {
    auto ret = salticidae::trim_all(salticidae::split(s, ";"));
    return std::make_pair(ret[0], ret[1]);
}

int main(int argc, char **argv) {
    Config config("hotstuff.conf");

    auto opt_idx = Config::OptValInt::create(0);
    auto opt_replicas = Config::OptValStrVec::create();
    auto opt_max_async_num = Config::OptValInt::create(0);
    auto opt_cid = Config::OptValInt::create(-1);
    auto opt_max_cli_msg = Config::OptValInt::create(65536); // 64K by default
    auto opt_size = Config::OptValInt::create(12);
    auto opt_tps = Config::OptValInt::create(0);

    auto shutdown = [&](int) { ec.stop(); };
    salticidae::SigEvent ev_sigint(ec, shutdown);
    salticidae::SigEvent ev_sigterm(ec, shutdown);
    ev_sigint.add(SIGINT);
    ev_sigterm.add(SIGTERM);

    mn = std::make_unique<Net>(ec, Net::Config().max_msg_size(opt_max_cli_msg->get()));
    mn->reg_handler(client_resp_cmd_handler);
    mn->start();

    config.add_opt("idx", opt_idx, Config::SET_VAL);
    config.add_opt("cid", opt_cid, Config::SET_VAL);
    config.add_opt("replica", opt_replicas, Config::APPEND);
    config.add_opt("max-async", opt_max_async_num, Config::SET_VAL);
    config.add_opt("max-cli-msg", opt_max_cli_msg, Config::SET_VAL, 'S', "the maximum client message size");
    config.add_opt("size", opt_size, Config::SET_VAL);
    config.add_opt("tps", opt_tps, Config::SET_VAL);
    config.parse(argc, argv);
    auto idx = opt_idx->get();
    max_async_num = opt_max_async_num->get();
    std::vector<std::string> raw;
    for (const auto &s: opt_replicas->get())
    {
        auto res = salticidae::trim_all(salticidae::split(s, ","));
        if (res.size() < 1)
            throw HotStuffError("format error");
        raw.push_back(res[0]);
    }

    if (!(0 <= idx && (size_t)idx < raw.size() && raw.size() > 0))
        throw std::invalid_argument("out of range");
    cid = opt_cid->get() != -1 ? opt_cid->get() : idx;
    for (const auto &p: raw)
    {
        auto _p = split_ip_port_cport(p);
        size_t _;
        replicas.push_back(NetAddr(NetAddr(_p.first).ip, htons(stoi(_p.second, &_))));
    }

    cmd_size = opt_size->get();

    tps = opt_tps->get();

    if (tps > 0) {
        if (tps <= MAX_TICK_HZ)
            tick_sleep = 1.0d / tps;
        else
            tick_sleep = 1.0d / MAX_TICK_HZ;
        ticker = TimerEvent(ec, std::bind(&tick_cb, _1));
        ticker.add(tick_sleep);
    }

    nfaulty = (replicas.size() - 1) / 3;
    HOTSTUFF_LOG_INFO("nfaulty = %zu", nfaulty);
    connect_all();
    start_send();
    ec.dispatch();

#ifdef HOTSTUFF_ENABLE_BENCHMARK
    for (const auto &e: elapsed)
    {
        char fmt[64];
        struct tm *tmp = localtime(&e.first.tv_sec);
        strftime(fmt, sizeof fmt, "%Y-%m-%d %H:%M:%S.%%06u [hotstuff info] %%.6f\n", tmp);
        fprintf(stderr, fmt, e.first.tv_usec, e.second);
    }
#endif
    return 0;
}
