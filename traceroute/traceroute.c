#include <arpa/inet.h>
#include <asm-generic/errno-base.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>

const int NUM_PROBES = 3;
const int PORT_BIND = 83295;
const int PORT_SEND_BASE = 32768 + 666;
const int MTU_MAX_SIZE = 1500;
const int ICMP_HDR_SZ = 8;
const int UDP_HDR_SZ = 8;

int sigalrm_triggered;

struct args {
  char *host;
  int nprobes;
};

struct traceopts {
  int nprobes;
  int max_ttl;

  int sendfd;
  int recvfd;
  int bindfd;

  struct sockaddr *send_addr;
  socklen_t send_addrlen;

  struct sockaddr *bind_addr;
  int bind_port;
  socklen_t bind_addrlen;
};

#define eprintf(...) fprintf(stderr, __VA_ARGS__)
#define unused(x) (void)(x)
#define ihl_to_bytes(ihl) ((ihl) << 2)

void exit_usage(char *pname) {
  eprintf("usage: %s -p <probes> <hostname>\n", pname);
  exit(EXIT_FAILURE);
}

int set_sockaddr_port(struct sockaddr *addr, int port) {
  switch (addr->sa_family) {
  case AF_INET: {
    struct sockaddr_in *addrv4 = (struct sockaddr_in *)addr;
    addrv4->sin_port = htons(port);
    return 0;
  }
  default:
    eprintf("set_sockaddr_port: setter for family %d not implemented",
            addr->sa_family);
    return -1;
  }
}

char *sockaddr_ntop_host(const struct sockaddr *addr) {
  static char str[INET_ADDRSTRLEN];

  switch (addr->sa_family) {
  case AF_INET: {
    struct sockaddr_in *sin = (struct sockaddr_in *)addr;

    if (inet_ntop(AF_INET, &sin->sin_addr, str, sizeof(str)) == NULL)
      return NULL;

    return str;
  }
  default:
    eprintf("sockaddr_ntop_host: setter for family %d not implemented",
            addr->sa_family);
    return NULL;
  }
}

struct args parse_args(int argc, char **argv) {
  int opt;
  struct args args = {.nprobes = NUM_PROBES};

  opterr = 0;
  while ((opt = getopt(argc, argv, "p:")) != -1) {
    switch (opt) {
    case 'p':
      if ((args.nprobes = atoi(optarg)) < 1) {
        exit_usage(argv[0]);
      }
      break;
    default:
      exit_usage(argv[0]);
    }
  }

  if (optind != argc - 1) {
    exit_usage(argv[0]);
  }

  args.host = argv[optind];
  return args;
}

enum recv_probe_ret {
  RECV_PROBE_SYSTEM_ERR,
  RECV_PROBE_TIMEOUT,
  RECV_PROBE_TIMXCEED,
  RECV_PROBE_UNREACH,
};

enum recv_probe_ret recv_probe(struct traceopts *traceopts, int dport) {
  char recvbuf[MTU_MAX_SIZE];
  int ret;

  sigalrm_triggered = 0;
  alarm(3);
  for (;;) {
    if (sigalrm_triggered) {
      ret = RECV_PROBE_TIMEOUT;
      break;
    }

    int recvlen = recvfrom(traceopts->recvfd, recvbuf, sizeof(recvbuf), 0,
                           traceopts->bind_addr, &traceopts->bind_addrlen);

    if (recvlen < 0) {
      if (errno == EINTR) {
        continue;
      } else {
        perror("recvfrom");
        ret = RECV_PROBE_SYSTEM_ERR;
        break;
      }
    }

    if (recvlen < 8) {
      // not enough data to parse the IP header
      continue;
    }

    struct ip *ip = (struct ip *)recvbuf;
    int iplen = ihl_to_bytes(ip->ip_hl);

    int icmplen;
    if ((icmplen = recvlen - iplen) < ICMP_HDR_SZ) {
      // not enough data to parse the ICMP header
      continue;
    }

    struct icmp *icmp = (struct icmp *)(recvbuf + iplen);
    if ((icmp->icmp_type != ICMP_TIMXCEED ||
         icmp->icmp_code != ICMP_TIMXCEED_INTRANS) &&
        icmp->icmp_type != ICMP_UNREACH) {
      continue;
    }

    if ((unsigned long)icmplen < ICMP_HDR_SZ + sizeof(struct ip)) {
      // not enough data to parse the IP header expected on the ICMP data
      continue;
    }

    struct ip *orig_ip = (struct ip *)(recvbuf + iplen + ICMP_HDR_SZ);
    int orig_iplen = ihl_to_bytes(orig_ip->ip_hl);

    if (icmplen < ICMP_HDR_SZ + orig_iplen + UDP_HDR_SZ) {
      // not enough data to parse the UDP header expected on the IP data
      continue;
    }

    struct udphdr *orig_udp =
        (struct udphdr *)(recvbuf + iplen + ICMP_HDR_SZ + orig_iplen);

    if (orig_ip->ip_p == IPPROTO_UDP && orig_udp->uh_dport == htons(dport) &&
        orig_udp->uh_sport == htons(traceopts->bind_port)) {
      if (icmp->icmp_type == ICMP_TIMXCEED) {
        ret = RECV_PROBE_TIMXCEED;
      } else {
        if (icmp->icmp_code == ICMP_UNREACH_PORT) {
          // TODO (phos)
          // This assumes that the destination port will be blocked on the
          // host but there's a very smol possibility that it isn't right?
          // Should we switch to check that the dst address on the ip packet
          // is the same that we specified originally?
          ret = RECV_PROBE_UNREACH;
        } else {
          eprintf("recv_probe: icmp packet of type ICMP_UNREACH has unhandled "
                  "icmp code %d\n",
                  icmp->icmp_code);
          return RECV_PROBE_SYSTEM_ERR;
        }
      }
      break;
    }
  }

  return ret;
}

int get_host(struct sockaddr *sa, socklen_t sa_len, char host[NI_MAXHOST]) {
  return getnameinfo(sa, sa_len, host, NI_MAXHOST, NULL, 0, 0);
}

int traceloop(struct traceopts *traceopts) {
  int ttl, done = 0;

  for (ttl = 1; ttl < traceopts->max_ttl && !done; ttl++) {
    int probe, send_probe = 1;
    printf("%2d. ", ttl);

    for (probe = 0; probe < traceopts->nprobes && send_probe; probe++) {
      int dport = PORT_SEND_BASE + ttl + probe;
      char msg[4] = "owo";

      if (set_sockaddr_port(traceopts->send_addr, dport) == -1) {
        return -1;
      }

      if (setsockopt(traceopts->sendfd, IPPROTO_IP, IP_TTL, &ttl,
                     sizeof(ttl)) == -1) {
        perror("setsockopt");
        return -1;
      }

      if (sendto(traceopts->sendfd, msg, strlen(msg), 0, traceopts->send_addr,
                 traceopts->send_addrlen) == -1) {
        perror("sendto");
        return -1;
      }

      fflush(stdout);

      enum recv_probe_ret probe_ret = recv_probe(traceopts, dport);
      switch (probe_ret) {
      case RECV_PROBE_SYSTEM_ERR:
        return -1;
      case RECV_PROBE_TIMEOUT:
        printf(" *");
        break;
      case RECV_PROBE_TIMXCEED:
      case RECV_PROBE_UNREACH: {
        char *host_addr = sockaddr_ntop_host(traceopts->bind_addr);
        char host[NI_MAXHOST];

        if (get_host(traceopts->bind_addr, traceopts->bind_addrlen, host) ==
            0) {
          printf(" %s (%s)", host, host_addr);
        } else {
          printf(" %s", host_addr);
        }

        if (probe_ret == RECV_PROBE_UNREACH) {
          done = 1;
        }

        send_probe = 0;
      } break;
      default:
        eprintf("recv_probe: return code %d not handled\n", probe_ret);
        return -1;
      }

      if (done == 1) {
        break;
      }
    }

    printf("\n");
  }
  return 0;
}

void sigalrm_handler(int sig) {
  unused(sig);
  sigalrm_triggered = 1;
}

int init_sigalrm_handler() {
  struct sigaction sa = {.sa_handler = sigalrm_handler};
  return sigaction(SIGALRM, &sa, NULL);
}

int main(int argc, char **argv) {
  int ret;
  struct traceopts traceopts;
  struct addrinfo hints, *res;
  struct args args;

  args = parse_args(argc, argv);

  if (init_sigalrm_handler() != 0) {
    perror("init_sigalrm_handler");
    return EXIT_FAILURE;
  }

  hints.ai_family = AF_INET;
  hints.ai_socktype = 0;
  if ((ret = getaddrinfo(args.host, NULL, &hints, &res)) != 0) {
    if (ret == EAI_SYSTEM) {
      perror("getaddrinfo");
    } else {
      eprintf("getaddrinfo: %s\n", gai_strerror(ret));
    }
    return EXIT_FAILURE;
  }

  traceopts.nprobes = args.nprobes;
  traceopts.max_ttl = 30; /* TODO: set via console argument */

  traceopts.send_addrlen = res->ai_addrlen;
  traceopts.send_addr = res->ai_addr; /* TODO: what about the next matches? */

  traceopts.bind_addrlen = traceopts.send_addrlen;
  traceopts.bind_addr = calloc(1, traceopts.bind_addrlen);
  traceopts.bind_addr->sa_family = res->ai_family;
  traceopts.bind_port = (getpid() & 0xffff) | 0x8000;

  traceopts.sendfd = socket(res->ai_family, SOCK_DGRAM, 0);
  traceopts.recvfd = socket(res->ai_family, SOCK_RAW, IPPROTO_ICMP);
  traceopts.bindfd = traceopts.sendfd;

  if (set_sockaddr_port(traceopts.bind_addr, traceopts.bind_port) == -1) {
    goto e2;
  }

  if (bind(traceopts.bindfd, traceopts.bind_addr, traceopts.bind_addrlen) ==
      -1) {
    perror("bind");
    goto e2;
  }

  if (traceopts.sendfd == -1 || traceopts.recvfd == -1) {
    perror("socket");
    goto e2;
  }

  if (traceloop(&traceopts) != 0) {
    goto e2;
  }

  free(traceopts.bind_addr);
  freeaddrinfo(res);
  return EXIT_SUCCESS;

e2:
  free(traceopts.bind_addr);
  freeaddrinfo(res);
  return EXIT_FAILURE;
}
