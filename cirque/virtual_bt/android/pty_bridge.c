/*
 * Copyright 2026 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * pty_bridge: Android-guest HCI H4 <-> Cirque Virtual Bluetooth TCP bridge.
 *
 * PURPOSE
 * -------
 * The Android emulator's Bluetooth HAL (android.hardware.bluetooth-service)
 * talks HCI H4 (UART framing) to a character device. By default that device
 * is backed by the emulator's built-in Bluetooth simulator, which Cirque does
 * not use. This program runs *inside the Android guest* and replaces that
 * device with a pseudo-terminal whose far end is a TCP connection to Cirque's
 * userspace VirtualBluetoothServer running on the host. The Android stack
 * then shares the same virtual LE link layer as the Docker IoT end devices,
 * so CHIPTool can do BLE PASE against chip-all-clusters-app with no kernel
 * modules, no bluetoothd, and no emulator radio daemons involved.
 *
 * DATA PATH
 * ---------
 *   Android BT HAL  --H4 bytes-->  /dev/bluetooth0 (symlink)
 *                                      |
 *                                      v  PTY slave
 *                               pty_bridge (PTY master)
 *                                      |
 *                                      v  TCP, TCP_NODELAY
 *                 VirtualBluetoothServer <host_ip>:<port> (host side)
 *                                      |
 *                                      v
 *                 Cirque virtual controller + LE link layer relay
 *
 * The bridge is byte-transparent: it does not parse H4. Framing, HCI command
 * and event handling, and link-layer relay all live in the Cirque server
 * (cirque/virtual_bt/{server,controller,link_layer}.py).
 *
 * WIRE PROTOCOL
 * -------------
 * Immediately after connecting, the bridge sends one ASCII line:
 *
 *     BIND <bind_id>\n
 *
 * This is the VirtualBluetoothServer "raw H4 bind" handshake: it tells the
 * server which virtual controller id (default "android_hci0") this TCP
 * stream carries. Everything after that line, in both directions, is raw H4.
 *
 * USAGE
 * -----
 *     pty_bridge <pty_symlink_path> <host_ip> <port> [bind_id]
 *
 *   pty_symlink_path  Path the HAL opens, e.g. /dev/bluetooth0. Any existing
 *                     file at this path is unlinked and replaced by a symlink
 *                     to the freshly allocated PTY slave (chmod 0666 so the
 *                     bluetooth uid can open it).
 *   host_ip           IPv4 address of the host running the Cirque server, as
 *                     seen from the guest (typically the Docker gateway).
 *   port              TCP port of VirtualBluetoothServer's H4 listener.
 *   bind_id           Virtual controller id for the BIND line
 *                     (default: android_hci0).
 *
 * The Python side (cirque/nodes/androiddockernode.py, start_pty_bridge)
 * pushes this binary to /data/local/tmp, launches it, and then restarts the
 * guest's bt_vhci_forwarder / Bluetooth HAL so the HAL reopens the symlink.
 *
 * LIFECYCLE
 * ---------
 *   1. Allocate a PTY master (posix_openpt/grantpt/unlockpt), raw mode.
 *   2. Connect to <host_ip>:<port>, send "BIND <bind_id>\n".
 *   3. Point <pty_symlink_path> at the PTY slave.
 *   4. poll() both fds and copy bytes PTY->TCP and TCP->PTY until the TCP
 *      peer closes, a fatal I/O error occurs, or SIGINT/SIGTERM arrives.
 *   5. Print byte counters for each direction and exit 0.
 *
 * The symlink is created *after* the TCP connection succeeds so the HAL
 * never attaches to a PTY with no server behind it. EIO on the PTY master
 * is tolerated: it is what Linux returns while no process has the slave
 * open (e.g. while the HAL restarts).
 *
 * EXIT CODES
 * ----------
 *   0  clean shutdown (signal, peer closed, or poll error after start)
 *   1  bad arguments
 *   2  posix_openpt failed
 *   3  grantpt failed
 *   4  unlockpt failed
 *   5  ptsname failed
 *   6  socket() failed
 *   7  host_ip is not a valid IPv4 address
 *   8  connect() failed (server not reachable)
 *   9  write of the BIND line failed
 *  10  symlink() failed
 *
 * BUILD
 * -----
 * Built by build_pty_bridge.sh with the Android NDK as a *static* x86_64
 * binary (API 34) so it has no dependency on guest libc versions and runs
 * from /data/local/tmp on the emulator image used by Cirque.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <signal.h>
#include <termios.h>

/* Copy buffer per poll() wakeup. H4 packets are far smaller than this; the
 * value only bounds how much is moved per read()/write() pair. */
#define BUF_SIZE 4096
#define MAX_EIO_RETRIES 100

/* Cleared by SIGINT/SIGTERM to leave the forwarding loop gracefully. */
static volatile int g_running = 1;

static void sig_handler(int sig) {
    (void)sig;
    g_running = 0;
}

/* Writes `n` bytes from `buf` to the TCP socket `sock_fd`. */
static void write_all_to_tcp(int sock_fd, const uint8_t *buf, ssize_t n) {
    ssize_t sent = 0;
    while (g_running && sent < n) {
        ssize_t s = write(sock_fd, buf + sent, n - sent);
        if (s > 0) {
            sent += s;
            continue;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            usleep(1000);
            continue;
        }
        perror("write to tcp");
        g_running = 0;
        break;
    }
}

/* Writes `n` bytes from `buf` to the PTY master `master_fd` with bounded EIO
 * retry while the Android Bluetooth HAL slave fd is re-opening. */
static void write_all_to_pty(int master_fd, const uint8_t *buf, ssize_t n) {
    ssize_t sent = 0;
    int eio_retries = 0;
    while (g_running && sent < n) {
        ssize_t s = write(master_fd, buf + sent, n - sent);
        if (s > 0) {
            sent += s;
            continue;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            usleep(1000);
            continue;
        }
        if (errno == EIO) {
            if (++eio_retries > MAX_EIO_RETRIES) {
                fprintf(stderr,
                        "[pty_bridge] EIO retry limit reached writing to PTY "
                        "(%d retries), dropping frame\n",
                        MAX_EIO_RETRIES);
                break;
            }
            usleep(1000);
            continue;
        }
        perror("write to pty");
        g_running = 0;
        break;
    }
}

int main(int argc, char *argv[]) {
    if (argc < 4) {
        fprintf(
            stderr,
            "Usage: %s <pty_symlink_path> <host_ip> <port> [bind_id]\n",
            argv[0]);
        return 1;
    }

    const char *symlink_path = argv[1];
    const char *host_ip = argv[2];
    int port = atoi(argv[3]);
    const char *bind_id = (argc >= 5) ? argv[4] : "android_hci0";

    /* SIGPIPE is ignored so a server disconnect surfaces as EPIPE from
     * write() (handled in the loop) instead of killing the process. stdout
     * and stderr are unbuffered because the bridge is normally started
     * detached under `adb shell` and its log lines are what the Python
     * side tails to confirm liveness. */
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    signal(SIGPIPE, SIG_IGN);

    setbuf(stdout, 0);
    setbuf(stderr, 0);

    /* Step 1: allocate the PTY pair. The HAL will open the slave; we keep
     * the master and shuttle its bytes to/from the TCP socket. */
    int master_fd = posix_openpt(O_RDWR | O_NOCTTY);
    if (master_fd < 0) {
        perror("posix_openpt");
        return 2;
    }
    if (grantpt(master_fd) < 0) {
        perror("grantpt");
        close(master_fd);
        return 3;
    }
    if (unlockpt(master_fd) < 0) {
        perror("unlockpt");
        close(master_fd);
        return 4;
    }

    char *slave_name = ptsname(master_fd);
    if (!slave_name) {
        perror("ptsname");
        close(master_fd);
        return 5;
    }
    printf("[pty_bridge] Created PTY master fd=%d, slave=%s\n",
           master_fd, slave_name);

    /* Raw mode is mandatory: with the default line discipline the kernel
     * would translate CR/LF, echo input and interpret control bytes, all of
     * which corrupt binary H4 traffic. */
    struct termios tios;
    if (tcgetattr(master_fd, &tios) == 0) {
        cfmakeraw(&tios);
        tcsetattr(master_fd, TCSANOW, &tios);
    }

    /* Step 2: connect to the Cirque Virtual Bluetooth H4 TCP listener.
     * TCP_NODELAY keeps small HCI command/event packets from being
     * coalesced by Nagle, which would add visible latency to every HCI
     * round trip during scanning and PASE. */
    printf("[pty_bridge] Connecting to %s:%d...\n", host_ip, port);
    int sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_fd < 0) {
        perror("socket");
        close(master_fd);
        return 6;
    }

    int nodelay = 1;
    setsockopt(sock_fd, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));

    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, host_ip, &serv_addr.sin_addr) <= 0) {
        perror("inet_pton");
        close(master_fd);
        close(sock_fd);
        return 7;
    }

    if (connect(sock_fd, (struct sockaddr *)&serv_addr,
                sizeof(serv_addr)) < 0) {
        perror("connect");
        close(master_fd);
        close(sock_fd);
        return 8;
    }

    /* Step 3: identify ourselves. The server associates this TCP stream
     * with virtual controller <bind_id>; all later bytes are raw H4. */
    char bind_msg[128];
    snprintf(bind_msg, sizeof(bind_msg), "BIND %s\n", bind_id);
    if (write(sock_fd, bind_msg, strlen(bind_msg)) < 0) {
        perror("write BIND");
        close(master_fd);
        close(sock_fd);
        return 9;
    }
    printf("[pty_bridge] Connected to Cirque! Sent: %s", bind_msg);

    /* Step 4: publish the PTY slave at the path the HAL opens. This is
     * done only now, after the server link is up, so the HAL can never
     * attach to a dead bridge. The slave is made world-readable/writable
     * because the HAL runs as the bluetooth uid, not root. */
    unlink(symlink_path);
    if (symlink(slave_name, symlink_path) < 0) {
        perror("symlink");
        close(master_fd);
        close(sock_fd);
        return 10;
    }
    chmod(slave_name, 0666);
    printf("[pty_bridge] Pointed %s -> %s\n", symlink_path, slave_name);

    /* Step 5: forwarding loop. Both fds are non-blocking and multiplexed
     * with poll(); the 1 s timeout only exists so g_running is re-checked
     * after a signal even when no traffic flows. Short writes are retried
     * until the whole chunk is delivered so H4 packets are never split
     * across a dropped tail. */
    fcntl(master_fd, F_SETFL, O_NONBLOCK);
    fcntl(sock_fd, F_SETFL, O_NONBLOCK);

    struct pollfd fds[2];
    fds[0].fd = master_fd;
    fds[0].events = POLLIN;
    fds[1].fd = sock_fd;
    fds[1].events = POLLIN;

    unsigned char buf[BUF_SIZE];
    long total_pty_to_tcp = 0;
    long total_tcp_to_pty = 0;

    printf("[pty_bridge] Entering forwarding loop...\n");

    while (g_running) {
        int ret = poll(fds, 2, 1000);
        if (ret < 0) {
            if (errno == EINTR) continue;
            perror("poll");
            break;
        }
        if (ret == 0) continue;

        /* PTY -> TCP: host-to-controller H4 (HCI commands, ACL data from
         * the Android stack). EIO on read means no process currently has
         * the slave open (HAL restarting); treat it as "no data". */
        if (fds[0].revents & POLLIN) {
            ssize_t n = read(master_fd, buf, sizeof(buf));
            if (n > 0) {
                total_pty_to_tcp += n;
                write_all_to_tcp(sock_fd, buf, n);
            } else if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK &&
                       errno != EIO) {
                perror("read pty");
                break;
            } else if (n == 0 || (n < 0 && errno == EIO)) {
                usleep(20000);
            }
        } else if (fds[0].revents & POLLHUP) {
            /* Slave end of PTY closed (e.g. forwarder restarting).
             * Throttle to avoid 100% CPU busy-spin in poll(). */
            usleep(20000);
        }

        /* TCP -> PTY: controller-to-host H4 (HCI events, ACL data from
         * the virtual link layer). A write EIO (slave not yet reopened by
         * the HAL) is retried rather than treated as fatal. A zero-length
         * read means the Cirque server went away, which ends the bridge. */
        if (fds[1].revents & POLLIN) {
            ssize_t n = read(sock_fd, buf, sizeof(buf));
            if (n > 0) {
                total_tcp_to_pty += n;
                write_all_to_pty(master_fd, buf, n);
            } else if (n == 0) {
                printf("[pty_bridge] TCP peer closed connection.\n");
                break;
            } else if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                perror("read tcp");
                break;
            }
        }

        if ((fds[0].revents & (POLLERR | POLLNVAL)) ||
            (fds[1].revents & (POLLERR | POLLHUP | POLLNVAL))) {
            printf("[pty_bridge] Poll error: fds[0]=0x%x fds[1]=0x%x\n",
                   fds[0].revents, fds[1].revents);
            break;
        }
    }

    printf("[pty_bridge] Exiting. Stats: PTY->TCP: %ld, TCP->PTY: %ld\n",
           total_pty_to_tcp, total_tcp_to_pty);
    close(master_fd);
    close(sock_fd);
    return 0;
}
