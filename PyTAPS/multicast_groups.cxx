/*
 * Copyright 2019, Akamai Technologies, Inc.
 * Jake Holland <jholland@akamai.com>
 * (MIT-licensed, please see LICENSE file in python-asyncio-taps for details)
 */

/*
g++ -c -fPIC multicast_groups.cxx -o multicast_groups.o
g++ multicast_groups.o -shared -Wl,-soname,libpymcast.so -o libpymcast.so
 */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <string.h>
#include <errno.h>
#include <deque>
#include <string>
#include <sstream>

extern "C" {
  int join_ssm(int sockfd, int iface_idx, int af,
      void* source_ip, void* group_ip);
  int leave_ssm(const char* ifname, const char* source_ip, const char* group_ip);
  int join_asm(const char* ifname, const char* group_ip);
  int leave_asm(const char* ifname, const char* group_ip);

  int errmsg_count();
  const char* errmsg(int idx);
  void clear_errors();
}

struct validate_ctx {
  std::deque<std::string> errors;
  unsigned int max_errs = 15;
};
static validate_ctx g_vctx;

enum MC_LOG_LEVEL {
  MC_LLERR,
  MC_LLWRN,
  MC_LLVRB,
  MC_LLDBG
};

static const char* log_str(MC_LOG_LEVEL level) {
  switch(level) {
    case MC_LLERR:
      return "ERR";
    case MC_LLWRN:
      return "WARN";
    case MC_LLVRB:
      return "VERBOSE";
    case MC_LLDBG:
      return "DEBUG";
    default:
      return "UNKNOWN";
  }
}

static void log_err(MC_LOG_LEVEL level, const char* msg) {
  if (g_vctx.errors.size() > g_vctx.max_errs) {
    g_vctx.errors.pop_front();
  }
  std::ostringstream sm;
  sm << log_str(level) << ": " << msg;
  g_vctx.errors.push_back(sm.str());
}

int errmsg_count() {
  return static_cast<int>(g_vctx.errors.size());
}

const char* errmsg(int idx) {
  if (idx < 0 || idx >= g_vctx.errors.size()) {
    return NULL;
  }
  return g_vctx.errors[idx].c_str();
}

void clear_errors() {
  g_vctx.errors.clear();
}

int join_ssm(int sockfd, int iface_idx, int proto_v,
    void* source_ip, void* group_ip) {

  if (proto_v != 4 && proto_v != 6) {
    char temp[1024];
    snprintf(temp, sizeof(temp),
        "join_ssm: invalid protocol version(%d, neither 4 nor 6)", proto_v);
    log_err(MC_LLERR, temp);
    return -1;
  }

  int af = 0;
  switch(proto_v) {
    case 4:
      af = AF_INET;
      break;
    case 6:
      af = AF_INET6;
      break;
    default:
      log_err(MC_LLERR, "join_ssm: internal error--unknown proto_v after check");
      return -1;
  }

  if (sockfd <= 0) {
    char temp[1024];
    snprintf(temp, sizeof(temp), "join_ssm: invalid sockfd(%d)", sockfd);
    log_err(MC_LLERR, temp);
    return -1;
  }
  if (iface_idx <= 0) {
    char temp[1024];
    snprintf(temp, sizeof(temp), "join_ssm: invalid iface_idx(%d)", iface_idx);
    log_err(MC_LLERR, temp);
    return -1;
  }

  /*
  {
    const char* family;
    const char* src_s;
    const char* grp_s;
    char src[128], grp[128];
    switch(af) {
      case AF_INET: {
        src_s = inet_ntop(AF_INET, source_ip, src, sizeof(src));
        grp_s = inet_ntop(AF_INET, group_ip, grp, sizeof(grp));
        family = "ip4";
      }
      break;
      case AF_INET6: {
        src_s = inet_ntop(AF_INET6, source_ip, src, sizeof(src));
        grp_s = inet_ntop(AF_INET6, group_ip, grp, sizeof(grp));
        family = "ip6";
      }
      break;
    }
    printf("join_ssm: joining %s %s->%s\n", family, src_s, grp_s);
  }
  */

  struct group_source_req gsreq;
  bzero(&gsreq, sizeof(gsreq));
  gsreq.gsr_interface = iface_idx;

  int proto;
  switch(af) {
    case AF_INET: {
      struct sockaddr_in *src_in = reinterpret_cast<sockaddr_in*>(&gsreq.gsr_source);
      src_in->sin_family = AF_INET;
      bcopy(source_ip, &src_in->sin_addr, sizeof(struct in_addr));
      struct sockaddr_in *grp_in = reinterpret_cast<sockaddr_in*>(&gsreq.gsr_group);
      grp_in->sin_family = AF_INET;
      bcopy(group_ip, &grp_in->sin_addr, sizeof(struct in_addr));
      proto = IPPROTO_IP;
      break;
    }
    case AF_INET6: {
      struct sockaddr_in6 *src_in6 = reinterpret_cast<sockaddr_in6*>(&gsreq.gsr_source);
      src_in6->sin6_family = AF_INET6;
      bcopy(source_ip, &src_in6->sin6_addr, sizeof(struct in6_addr));
      struct sockaddr_in6 *grp_in6 = reinterpret_cast<sockaddr_in6*>(&gsreq.gsr_group);
      grp_in6->sin6_family = AF_INET6;
      bcopy(group_ip, &grp_in6->sin6_addr, sizeof(struct in6_addr));
      proto = IPPROTO_IPV6;
      break;
    }
    default:
      log_err(MC_LLERR, "join_ssm: internal error--unknown address family");
      return -1;
  }

  int rc;
  rc = setsockopt(sockfd, proto, MCAST_JOIN_SOURCE_GROUP, &gsreq, sizeof(gsreq));
  if (rc < 0) {
    char temp[1024];
    int taken = snprintf(temp, sizeof(temp), "join_ssm: sockopt error: ");
    if (taken > 0 && taken < 1023) {
      strerror_r(errno, &temp[taken], 1023-taken);
    }
    log_err(MC_LLERR, temp);
    return -1;
  }
  return 0;
}
