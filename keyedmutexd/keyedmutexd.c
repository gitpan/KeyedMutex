#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/un.h>
#include <unistd.h>

#define PROGNAME "keyedmutexd"
#define VERSION "0.01"

#define DEFAULT_SOCKPATH "/tmp/" PROGNAME ".sock"
#define DEFAULT_CONNS_SIZE 32
#define KEY_SIZE (16)

#ifndef MAX
#define MAX(x, y) ((x) < (y) ? (y) : (x))
#endif

#ifndef INLINE
#define INLINE __inline
#endif

enum conn_state_t {
  CS_NOCONN = 0,
  CS_KEYREAD,
  CS_OWNER,
  CS_NONOWNER
};

struct conn_t {
  enum conn_state_t state;
  char   key[KEY_SIZE];
  size_t key_offset;
};

static struct conn_t* conns; /* array of conns, conns[0] is for socket
				listen_fd+1 */
static int conns_length = 0; /* index of last valid conn + 1 */
static int conns_size = DEFAULT_CONNS_SIZE;  /* size of conns */
static int listen_fd;

#define OWNER_MSG "O"
#define RELEASE_MSG "R"

static void write_log(int fd, const char* status, const char* key)
{
  char hexkey[KEY_SIZE * 2 + 2];
  int i;
  
  if (key != NULL) {
    hexkey[0] = ' ';
    for (i = 0; i < KEY_SIZE; i++) {
      hexkey[i * 2 + 1] = ("0123456789abcdef")[(key[i] >> 4) & 0xf];
      hexkey[i * 2 + 2] = ("0123456789abcdef")[key[i] & 0xf];
    }
    hexkey[KEY_SIZE * 2 + 1] = '\0';
  } else {
    hexkey[0] = '\0';
  }
  
  printf("%d %s%s\n", fd, status, hexkey);
}

INLINE int reuse_addr(int fd)
{
  int arg = 1;
  return setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &arg, sizeof(arg));
}

INLINE int nonblock(int fd)
{
  return fcntl(fd, F_SETFL, O_NONBLOCK);
}

INLINE int nodelay(int fd)
{
  int arg = 0;
  return setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &arg, sizeof(arg));
}

INLINE void close_conn(int i)
{
  int fd = i + listen_fd + 1;
  close(fd);
  conns[i].state = CS_NOCONN;
  if (i + 1 == conns_length) {
    for (conns_length -= 1; conns_length != 0; conns_length--) {
      if (conns[conns_length - 1].state != CS_NOCONN) {
	break;
      }
    }
  }
  write_log(fd, "closed", NULL);
}

INLINE void setup_conn(int i)
{
  conns[i].state = CS_KEYREAD;
  conns[i].key_offset = 0;
}

static int owner_exists(const char* key)
{
  int i;
  
  for (i = 0; i < conns_length; i++) {
    if (conns[i].state == CS_OWNER
	&& memcmp(conns[i].key, key, KEY_SIZE) == 0) {
      return 1;
    }
  }
  return 0;
}

static void notify_nonowners(const char* key)
{
  int i;
  
  for (i = 0; i < conns_length; i++) {
    if (conns[i].state == CS_NONOWNER
	&& memcmp(conns[i].key, key, KEY_SIZE) == 0) {
      int fd = i + listen_fd + 1;
      if (write(fd, RELEASE_MSG, 1) <= 0) {
	close_conn(i);
      } else {
	write_log(fd, "notify", key);
	setup_conn(i);
      }
    }
  }
}

static void loop(void)
{
  while (1) {
    
    fd_set readfds;
    struct timeval tv = { 60, 0 };
    int i, noconn_exists = conns_length < conns_size;

    /* wait for a new connection or data */
    FD_ZERO(&readfds);
    for (i = 0; i < conns_length; i++) {
      switch (conns[i].state) {
      case CS_KEYREAD:
      case CS_OWNER:
      case CS_NONOWNER:
	FD_SET(i + listen_fd + 1, &readfds);
	break;
      case CS_NOCONN:
	noconn_exists = 1;
	break;
      }
    }
    if (noconn_exists) {
      FD_SET(listen_fd, &readfds);
    }
    if (select(listen_fd + conns_length + 1, &readfds, NULL, NULL, &tv) <= 0) {
      continue;
    }
    
    /* accept new connections */
    if (FD_ISSET(listen_fd, &readfds)) {
      int fd;
      do {
	fd = accept(listen_fd, NULL, NULL);
	if (fd != -1) {
	  nodelay(fd);
	  i = fd - listen_fd - 1;
	  assert(0 <= i && i < conns_size);
	  assert(conns[i].state == CS_NOCONN);
	  setup_conn(i);
	  conns_length = MAX(i + 1, conns_length);
	  write_log(fd, "connected", NULL);
	}
      } while (fd != -1 && fd != listen_fd + conns_size);
    }
    
    /* read data */
    for (i = 0; i < conns_length; i++) {
      int fd = i + listen_fd + 1;
      if (FD_ISSET(fd, &readfds)) {
	switch (conns[i].state) {
	case CS_KEYREAD:
	  {
	    int r = read(fd, conns[i].key + conns[i].key_offset,
			 KEY_SIZE - conns[i].key_offset);
	    if (r <= 0) {
	      close_conn(i);
	    } else {
	      if ((conns[i].key_offset += r) == KEY_SIZE) {
		if (owner_exists(conns[i].key)) {
		  conns[i].state = CS_NONOWNER;
		  write_log(fd, "notowner", conns[i].key);
		} else {
		  write(fd, OWNER_MSG, 1);
		  conns[i].state = CS_OWNER;
		  write_log(fd, "owner", conns[i].key);
		}
	      }
	    }
	  }
	  break;
	case CS_OWNER:
	  {
	    char ch;
	    int r = read(fd, &ch, 1);
	    if (r <= 0 || ch != RELEASE_MSG[0]) {
	      close_conn(i);
	    } else {
	      setup_conn(i);
	    }
	    write_log(fd, "release", conns[i].key);
	    notify_nonowners(conns[i].key);
	  }
	  break;
	case CS_NONOWNER:
	  close_conn(i);
	  break;
	default:
	  assert(0); /* should not reach here */
	  break;
	}
      }
    }
  }
}

static void usage(void)
{
  fprintf(stdout,
	  "Usage: " PROGNAME " [OPTION]...\n"
	  "\n"
	  "Keyedmutexd is a tiny daemon that acts as a mutex for supplied key.\n"
	  "\n"
	  "Options:\n"
	  " -f,--force            removes old socket file if exists\n"
	  " -s,--socket=SOCKET    unix domain socket or tcp port number\n"
	  "                       (default: %s)\n"
	  " -m,--maxconn=MAXCONN  number of max. connections (default: %d)\n"
	  "    --help             help\n"
	  "    --version          version\n"
	  "\n"
	  "Report bugs to http://labs.cybozu.co.jp/blog/kazuhoatwork/\n",
	  DEFAULT_SOCKPATH,
	  DEFAULT_CONNS_SIZE);
  exit(0);
}

static struct sockaddr_un sun;
static struct sockaddr_in sin;
static int use_tcp;
static int force;
static int print_info;
static struct option longopts[] = {
  { "socket", required_argument, NULL, 's' },
  { "maxconn", required_argument, NULL, 'm' },
  { "force", no_argument, NULL, 'f' },
  { "help", no_argument, &print_info, 'h' },
  { "version", no_argument, &print_info, 'v' },
  { NULL, no_argument, NULL, 0 },
};
  
int main(int argc, char** argv)
{
  int ch;
  
  sun.sun_family = AF_UNIX;
  strcpy(sun.sun_path, DEFAULT_SOCKPATH);
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = htonl(INADDR_ANY);
  
  while ((ch = getopt_long(argc, argv, "s:m:fhv", longopts, NULL)) != -1) {
    switch (ch) {
    case 's':
      {
	unsigned short p;
	if (sscanf(optarg, "%hu", &p) == 1) {
	  sin.sin_port = htons(p);
	  use_tcp = 1;
	} else {
	  strncpy(sun.sun_path, optarg, sizeof(sun.sun_path) - 1);
	  sun.sun_path[sizeof(sun.sun_path) - 1] = '\0';
	}
      }
      break;
    case 'f':
      force = 1;
      break;
    case 'm':
      if (sscanf(optarg, "%d", &conns_size) != 1 || conns_size <= 0) {
	fprintf(stderr, "invalid parameter \"-n\"\n");
	exit(1);
      }
      break;
    case 0:
      switch (print_info) {
      case 'h':
	usage();
	break;
      case 'v':
	fputs(PROGNAME " " VERSION "\n", stdout);
	exit(0);
      }
      break;
    default:
      fprintf(stderr, "unknown option: %s\n", argv[optind - 1]);
      exit(1);
    }
  }
  
  if ((conns = calloc(conns_size, sizeof(struct conn_t))) == NULL) {
    perror(NULL);
    exit(2);
  }
  
  if (use_tcp) {
    if ((listen_fd = socket(AF_INET, SOCK_STREAM, 0)) == -1
	|| reuse_addr(listen_fd) == -1
	|| nonblock(listen_fd) == -1
	|| bind(listen_fd, (struct sockaddr*)&sin, sizeof(sin)) == -1
	|| listen(listen_fd, 5) == -1) {
      perror("failed to open a listening socket");
      exit(3);
    }
  } else {
    if (force) {
      unlink(sun.sun_path);
    }
    if ((listen_fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1
	|| nonblock(listen_fd) == -1
	|| bind(listen_fd, (struct sockaddr*)&sun, sizeof(sun)) == -1
	|| listen(listen_fd, 5) == -1) {
      perror("failed to open a listening socket");
      exit(2);
    }
  }
  
  signal(SIGPIPE, SIG_IGN);
  
  loop();
  
  return 0;
}
