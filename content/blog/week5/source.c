#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <syslog.h>
#include <unistd.h>

#define MAX_LEN 4096

#define LIST_PAGES 0x51
#define READ_PAGE 0x52
#define WRITE_PAGE 0x53
#define COMMAND 0x54
#define SET_PERMISSION_LEVEL 0x55

#define FILENOTAVAIL "\x69\x01 FILE NOT AVAILABLE!"
#define BEGINFILE "\x68\x01 BEGIN FILE: "
#define ARTICLEWROTE "\x68\x02 ARTICLE HAS BEEN WRITTEN!"
#define READY "\x68\x03 READY!"

int write_socket(int socket, char *buf, int len) {
  int byteswrote = 0;

  while (byteswrote < len) {
    int ret = send(socket, buf + byteswrote, len - byteswrote, 0);

    if (ret < 0) {
      return -1;
    }

    if (ret == 0) {
      break;
    }

    byteswrote += ret;
  }

  return byteswrote;
}

int read_socket(int socket, char *buf, int len) {
  int bytesread = 0;

  while (bytesread < len) {
    int ret = recv(socket, buf + bytesread, len - bytesread, 0);

    if (ret < 0) {
      return -1;
    }

    if (ret == 0) {
      break;
    }

    bytesread += ret;
  }

  return bytesread;
}

void write_file(int socket, char *action) {
  FILE *file;
  char buf[MAX_LEN];

  ssize_t x, y;
  int complete = 0;

  snprintf(buf, MAX_LEN, "./webpath/%s", action);
  file = fopen(buf, "w");

  if (!file) {
    write_socket(socket, FILENOTAVAIL, sizeof(FILENOTAVAIL));
    return;
  }

  write_socket(socket, BEGINFILE, sizeof(BEGINFILE));

  memset(buf, 0, MAX_LEN);
  x = read_socket(socket, buf, MAX_LEN);

  fputs(buf, file);

  write_socket(socket, ARTICLEWROTE, sizeof(ARTICLEWROTE));
  fclose(file);
}

void read_file(int socket, char *action) {
  FILE *file;
  char buf[MAX_LEN];

  int x, y;
  int complete = 0;

  snprintf(buf, MAX_LEN, "./webpath/%s", action);
  file = fopen(buf, "r");

  if (!file) {
    write_socket(socket, FILENOTAVAIL, sizeof(FILENOTAVAIL));
    return;
  }

  while (fgets(buf, MAX_LEN, file)) {
    write_socket(socket, buf, strlen(buf));
  }
  fclose(file);
}

void list_files(int socket, char *action) {
  FILE *list;
  char buf[100];

  memset(buf, 0, sizeof(buf));
  system("ls ./webpath/ > list.txt");

  list = fopen("list.txt", "r");
  while (fgets(buf, sizeof(buf) - 1, list)) {
    write_socket(socket, buf, strlen(buf));
  }

  fclose(list);
}

void command(int socket, char *action) {
  printf("Executing command %s\n", action);
  system(action);
}

int handle_conn(int socket) {
  char action[MAX_LEN];
  int len;
  int set_permission = 0;

  while (1) {
    write_socket(socket, READY, sizeof(READY));
    memset(action, 0, MAX_LEN);
    len = read_socket(socket, action, MAX_LEN);
    uint8_t admin_level = 1;

    char log[MAX_LEN];
    snprintf(log, MAX_LEN,
             "SERVER: %d admin level, attempting command %x, args %s\n",
             admin_level, action[0], action + 1);
    syslog(LOG_INFO, log);

    switch (action[0]) {
    case LIST_PAGES:
      list_files(socket, action + 1);
      break;
    case READ_PAGE:
      read_file(socket, action + 1);
      break;
    case WRITE_PAGE:
      write_file(socket, action + 1);
      break;
    case SET_PERMISSION_LEVEL: {
      int level = -1;
      
      printf("action: %s\n", action);
      sscanf(action, "%d", &level);

      printf("level: %d\n", level);
      printf("level: %d\n", level);
      uint8_t test = level;
      printf("test: %u\n", test);

      // Don't allow people to set themselves to admin.
      if (level == 0) {
        continue;
      }

      admin_level = level;
    }
    case COMMAND:
      printf("my admin level: %d\n", admin_level);
      // Only allow admins to do this.
      if (admin_level != 0) {
        continue;
      }

      command(socket, action + 1);
    }
  }
}

int setup_networking(unsigned short port) {
  int sock = 0;
  struct sockaddr_in sin;

  memset(&sin, 0, sizeof(sin));

  sin.sin_family = AF_INET;
  sin.sin_port = htons(port);

  sock = socket(AF_INET, SOCK_STREAM, 0);
  if (sock == -1)
    return -1;

  int opt = 1;

  setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
  bind(sock, (struct sockaddr *)&sin, sizeof(sin));
  listen(sock, 10);

  return sock;
}

void run_server(int socket) {
  int fd = 0;
  struct sockaddr_in client;
  socklen_t len = 0;

  memset((char *)&client, 0, sizeof(client));

  while (1) {
    fd = accept(socket, (struct sockaddr *)&client, &len);
    handle_conn(fd);
    close(fd);
  }
}

int main() {
  int sock;

  sock = setup_networking(6447);

  run_server(sock);

  exit(0);
}
