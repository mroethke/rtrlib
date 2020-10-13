/*
 * This file is part of RTRlib.
 *
 * This file is subject to the terms and conditions of the MIT license.
 * See the file LICENSE in the top level directory for more details.
 *
 * Website: http://rtrlib.realmv6.org/
 */

#include "ssh_transport_private.h"

#include "rtrlib/lib/alloc_utils_private.h"
#include "rtrlib/lib/log_private.h"
#include "rtrlib/lib/utils_private.h"
#include "rtrlib/rtrlib_export_private.h"
#include "rtrlib/transport/transport_private.h"

#include <assert.h>
#include <errno.h>
#include <libssh/libssh.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <poll.h>

#define SSH_DBG(fmt, sock, ...)                                                                                     \
	do {                                                                                                        \
		const struct tr_ssh_socket *tmp = sock;                                                             \
		lrtr_dbg("SSH Transport(%s@%s:%u): " fmt, tmp->config.username, tmp->config.host, tmp->config.port, \
			 ##__VA_ARGS__);                                                                            \
	} while (0)
#define SSH_DBG1(a, sock) SSH_DBG(a, sock)

enum connect_state {
	CONNECT_INIT,
	CONNECT_STARTED,
	CONNECT_AUTH_INIT,
	CONNECT_AUTH,
	CONNECT_CHANNEL_INIT,
	CONNECT_CHANNEL,
	CONNECT_SUBSYSTEM,
	CONNECT_DONE,
	CONNECT_STATE_COUNT,
};

struct tr_ssh_socket {
	ssh_session session;
	ssh_channel channel;
	struct tr_ssh_config config;
	char *ident;
	enum connect_state connect_state;
};

typedef int connect_state_func(struct tr_ssh_socket *ssh_socket);

static int tr_ssh_open(void *tr_ssh_sock);
static void tr_ssh_close(void *tr_ssh_sock);
static void tr_ssh_free(struct tr_socket *tr_sock);
static int tr_ssh_recv(const void *tr_ssh_sock, void *buf, const size_t buf_len, const time_t timeout);
static int tr_ssh_send(const void *tr_ssh_sock, const void *pdu, const size_t len, const time_t timeout);
static int tr_ssh_recv_async(const struct tr_ssh_socket *tr_ssh_sock, void *buf, const size_t buf_len);
static const char *tr_ssh_ident(void *tr_ssh_sock);
static int tr_ssh_get_fd(void *tr_ssh_sock);
static int tr_ssh_get_poll_flags(void *tr_ssh_sock);

static int do_connect_init(struct tr_ssh_socket *ssh_socket)
{
	SSH_DBG("tr_ssh_open: %s", ssh_socket, __func__);
	const struct tr_ssh_config *config = &ssh_socket->config;

	assert(!ssh_socket->channel);
	assert(!ssh_socket->session);

	ssh_socket->session = ssh_new();
	if (!ssh_socket->session) {
		SSH_DBG("%s: can't create ssh_session", ssh_socket, __func__);
		return TR_ERROR;
	}

	const int verbosity = SSH_LOG_NOLOG;

	ssh_options_set(ssh_socket->session, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);

	ssh_options_set(ssh_socket->session, SSH_OPTIONS_HOST, config->host);
	ssh_options_set(ssh_socket->session, SSH_OPTIONS_PORT, &(config->port));
	ssh_options_set(ssh_socket->session, SSH_OPTIONS_BINDADDR, config->bindaddr);
	ssh_options_set(ssh_socket->session, SSH_OPTIONS_USER, config->username);

	if (config->server_hostkey_path)
		ssh_options_set(ssh_socket->session, SSH_OPTIONS_KNOWNHOSTS, config->server_hostkey_path);

	if (config->client_privkey_path)
		ssh_options_set(ssh_socket->session, SSH_OPTIONS_IDENTITY, config->client_privkey_path);
	if (config->new_socket) {
		int fd;

		fd = config->new_socket(config->data);
		if (fd >= 0) {
			ssh_options_set(ssh_socket->session, SSH_OPTIONS_FD, &fd);
		} else {
			SSH_DBG1("tr_ssh_init: opening SSH connection failed", ssh_socket);
			return TR_ERROR;
		}
	}

	ssh_set_blocking(ssh_socket->session, 0);

	return TR_SUCCESS;
}

static int do_connect_started(struct tr_ssh_socket *ssh_socket) {
	SSH_DBG("tr_ssh_open: %s", ssh_socket, __func__);
	const int ret = ssh_connect(ssh_socket->session);

	if (ret == SSH_ERROR) {
		SSH_DBG("%s: opening ssh connection failed", ssh_socket, __func__);
		return TR_ERROR;
	} else if (ret == SSH_AGAIN) {
		return TR_INPROGRESS;
	}

	// check server identity
#if LIBSSH_VERSION_MAJOR > 0 || LIBSSH_VERSION_MINOR > 8
	if ((ssh_socket->config.server_hostkey_path) && (ssh_session_is_known_server(ssh_socket->session) != SSH_KNOWN_HOSTS_OK)) {
#else
	if ((ssh_socket->config.server_hostkey_path) && (ssh_is_server_known(ssh_socket->session) != SSH_SERVER_KNOWN_OK)) {
#endif
		SSH_DBG("%s: Wrong hostkey", ssh_socket, __func__);
		return TR_ERROR;
	}

	return TR_SUCCESS;
}

static int do_connect_auth_init(struct tr_ssh_socket *ssh_socket) {

	if (ssh_socket->config.client_privkey_path) {
		SSH_DBG("%s: Trying publickey authentication", ssh_socket, __func__);
		if (ssh_options_set(ssh_socket->session, SSH_OPTIONS_IDENTITY, ssh_socket->config.client_privkey_path) < 0) {
			SSH_DBG1("Could not set private key", ssh_socket);
			return TR_ERROR;
		}
	} else {
		SSH_DBG("%s: Trying password authentication", ssh_socket, __func__);
	}

	return TR_SUCCESS;
}

static int do_connect_auth(struct tr_ssh_socket *ssh_socket) {
	int ret;
	SSH_DBG("tr_ssh_open: %s", ssh_socket, __func__);

	if (ssh_socket->config.client_privkey_path) {
#if LIBSSH_VERSION_MAJOR > 0 || LIBSSH_VERSION_MINOR > 5
		ret = ssh_userauth_publickey_auto(ssh_socket->session, NULL, NULL);
#else /* else use libSSH version 0.5.0 */
		ret = ssh_userauth_autopubkey(ssh_socket->session, NULL);
#endif
	} else {
		ret = ssh_userauth_password(ssh_socket->session, NULL, ssh_socket->config.password);
	}

	SSH_DBG("SSH ret: %d", ssh_socket, ret);


	if (ret == SSH_AUTH_AGAIN) {
		return TR_INPROGRESS;
	} else if (ret == SSH_AUTH_SUCCESS) {

		return TR_SUCCESS;
	}

	SSH_DBG("Authentication Failed: %s", ssh_socket, ssh_get_error(ssh_socket->session));

	return TR_ERROR;

}

static int do_connect_channel_init(struct tr_ssh_socket *ssh_socket) {
	SSH_DBG("tr_ssh_open: %s", ssh_socket, __func__);

	ssh_socket->channel = ssh_channel_new(ssh_socket->session);
	if (!ssh_socket->channel)
		return TR_ERROR;

	return TR_SUCCESS;
}

static int do_connect_channel(struct tr_ssh_socket *ssh_socket) {
	SSH_DBG("tr_ssh_open: %s", ssh_socket, __func__);

	int ret = ssh_channel_open_session(ssh_socket->channel);

	SSH_DBG("ret: %d", ssh_socket, ret);


	if (ret == SSH_ERROR) {
		SSH_DBG("Error opening channel session: %s", ssh_socket, ssh_get_error(ssh_socket->session));
		return TR_ERROR;
	} else if (ret == SSH_AGAIN)
		return TR_INPROGRESS;


	return TR_SUCCESS;
}

static int do_connect_subsystem(struct tr_ssh_socket *ssh_socket) {
	SSH_DBG("tr_ssh_open: %s", ssh_socket, __func__);

	int ret = ssh_channel_request_subsystem(ssh_socket->channel, "rpki-rtr");

	if (ret == SSH_ERROR) {
		SSH_DBG("Error requesting subsystem rpki-rtr: %s", ssh_socket, ssh_get_error(ssh_socket->session));
		return TR_ERROR;
	} else if (ret == SSH_AGAIN) {
		return TR_INPROGRESS;
	}

	SSH_DBG1("Connection established", ssh_socket);

	return TR_SUCCESS;
}

static int do_connect_done(struct tr_ssh_socket *ssh_socket __attribute__((unused))) {
	SSH_DBG("tr_ssh_open: %s", ssh_socket, __func__);
	return TR_SUCCESS;
}

static connect_state_func* state_table[CONNECT_STATE_COUNT] = {
	do_connect_init,
	do_connect_started,
	do_connect_auth_init,
	do_connect_auth,
	do_connect_channel_init,
	do_connect_channel,
	do_connect_subsystem,
	do_connect_done,
};

/* WARNING: This function has cancelable sections! */
int tr_ssh_open(void *socket)
{
	struct tr_ssh_socket *ssh_socket = socket;
	int retval;

	do {
		retval = state_table[ssh_socket->connect_state](ssh_socket);

		if (retval == TR_SUCCESS) {
			switch (ssh_socket->connect_state) {
				case CONNECT_INIT:
					ssh_socket->connect_state = CONNECT_STARTED;
					break;

				case CONNECT_STARTED:
					ssh_socket->connect_state = CONNECT_AUTH_INIT;
					break;

				case CONNECT_AUTH_INIT:
					ssh_socket->connect_state = CONNECT_AUTH;
					break;

				case CONNECT_AUTH:
					ssh_socket->connect_state = CONNECT_CHANNEL_INIT;
					break;

				case CONNECT_CHANNEL_INIT:
					ssh_socket->connect_state = CONNECT_CHANNEL;
					break;

				case CONNECT_CHANNEL:
					ssh_socket->connect_state = CONNECT_SUBSYSTEM;
					break;

				case CONNECT_SUBSYSTEM:
					ssh_socket->connect_state = CONNECT_DONE;
					break;

				case CONNECT_DONE:
					break;

				default:
					SSH_DBG1("Illegal connect state reached", ssh_socket);
					retval = TR_ERROR;
			}
		}
	} while (retval == TR_SUCCESS && ssh_socket->connect_state != CONNECT_DONE);

	return retval;
}

void tr_ssh_close(void *tr_ssh_sock)
{
	struct tr_ssh_socket *socket = tr_ssh_sock;

	if (socket->channel) {
		if (ssh_channel_is_open(socket->channel))
			ssh_channel_close(socket->channel);
		ssh_channel_free(socket->channel);
		socket->channel = NULL;
	}
	if (socket->session) {
		ssh_disconnect(socket->session);
		ssh_free(socket->session);
		socket->session = NULL;
	}

	socket->connect_state = CONNECT_INIT;
	SSH_DBG1("Socket closed", socket);
}

void tr_ssh_free(struct tr_socket *tr_sock)
{
	struct tr_ssh_socket *tr_ssh_sock = tr_sock->socket;

	assert(!tr_ssh_sock->channel);
	assert(!tr_ssh_sock->session);

	SSH_DBG1("Freeing socket", tr_ssh_sock);

	lrtr_free(tr_ssh_sock->config.host);
	lrtr_free(tr_ssh_sock->config.bindaddr);
	lrtr_free(tr_ssh_sock->config.username);
	lrtr_free(tr_ssh_sock->config.client_privkey_path);
	lrtr_free(tr_ssh_sock->config.server_hostkey_path);

	if (tr_ssh_sock->ident)
		lrtr_free(tr_ssh_sock->ident);
	lrtr_free(tr_ssh_sock);
	tr_sock->socket = NULL;
}

int tr_ssh_recv_async(const struct tr_ssh_socket *tr_ssh_sock, void *buf, const size_t buf_len)
{
	const int rtval = ssh_channel_read_nonblocking(tr_ssh_sock->channel, buf, buf_len, false);

	if (rtval == 0) {
		if (ssh_channel_is_eof(tr_ssh_sock->channel) != 0) {
			SSH_DBG1("remote has sent EOF", tr_ssh_sock);
			return TR_CLOSED;
		} else {
			return TR_WOULDBLOCK;
		}
	} else if (rtval == SSH_ERROR) {
		SSH_DBG1("recv(..) error", tr_ssh_sock);
		return TR_ERROR;
	}
	return rtval;
}

int tr_ssh_recv(const void *tr_ssh_sock, void *buf, const size_t buf_len, const time_t timeout)
{
	ssh_channel rchans[2] = {((struct tr_ssh_socket *)tr_ssh_sock)->channel, NULL};
	struct timeval timev = {timeout, 0};
	int ret;

	ret = ssh_channel_select(rchans, NULL, NULL, &timev);
	if (ret == SSH_EINTR)
		return TR_INTR;
	else if (ret == SSH_ERROR)
		return TR_ERROR;

	if (ssh_channel_is_eof(((struct tr_ssh_socket *)tr_ssh_sock)->channel) != 0)
		return TR_ERROR;

	if (!rchans[0])
		return TR_WOULDBLOCK;

	return tr_ssh_recv_async(tr_ssh_sock, buf, buf_len);
}

int tr_ssh_send(const void *tr_ssh_sock, const void *pdu, const size_t len,
		const time_t timeout __attribute__((unused)))
{
	const struct tr_ssh_socket *ssh_socket = tr_ssh_sock;
	int ret = ssh_channel_write(((struct tr_ssh_socket *)tr_ssh_sock)->channel, pdu, len);

	if (ret == SSH_ERROR) {
		SSH_DBG("ssh write error: %s", ssh_socket, ssh_get_error(ssh_socket->session));
		return TR_ERROR;
	}

	return ret;
}

const char *tr_ssh_ident(void *tr_ssh_sock)
{
	size_t len;
	struct tr_ssh_socket *sock = tr_ssh_sock;

	assert(sock);

	if (sock->ident)
		return sock->ident;

	len = strlen(sock->config.username) + 1 + strlen(sock->config.host) + 1 + 5 + 1;
	sock->ident = lrtr_malloc(len);
	if (!sock->ident)
		return NULL;
	snprintf(sock->ident, len, "%s@%s:%u", sock->config.username, sock->config.host, sock->config.port);
	return sock->ident;
}

int tr_ssh_get_fd(void *tr_ssh_sock) {
	struct tr_ssh_socket *ssh_socket = tr_ssh_sock;

	return ssh_get_fd(ssh_socket->session);
}

int tr_ssh_get_poll_flags(void *tr_ssh_sock) {
	struct tr_ssh_socket *ssh_socket = tr_ssh_sock;

	int libssh_flags = ssh_get_poll_flags(ssh_socket->session);
	int flags = 0;

	if (libssh_flags & SSH_READ_PENDING) {
		flags |= POLLIN;
	}

	if (libssh_flags & SSH_WRITE_PENDING) {
		flags |= POLLOUT;
	}

	return flags;
}

RTRLIB_EXPORT int tr_ssh_init(const struct tr_ssh_config *config, struct tr_socket *socket)
{
	socket->close_fp = &tr_ssh_close;
	socket->free_fp = &tr_ssh_free;
	socket->open_fp = &tr_ssh_open;
	socket->recv_fp = &tr_ssh_recv;
	socket->send_fp = &tr_ssh_send;
	socket->ident_fp = &tr_ssh_ident;
	socket->get_fd_fp = &tr_ssh_get_fd;
	socket->get_poll_flags_fp = &tr_ssh_get_poll_flags;

	socket->socket = lrtr_calloc(1, sizeof(struct tr_ssh_socket));
	struct tr_ssh_socket *ssh_socket = socket->socket;

	ssh_socket->channel = NULL;
	ssh_socket->session = NULL;
	ssh_socket->config.host = lrtr_strdup(config->host);
	if (!ssh_socket->config.host)
		goto error;
	ssh_socket->config.port = config->port;

	ssh_socket->config.username = lrtr_strdup(config->username);
	if (!ssh_socket->config.username)
		goto error;

	if ((config->password && config->client_privkey_path) || (!config->password && !config->client_privkey_path))
		return TR_ERROR;

	if (config->bindaddr) {
		ssh_socket->config.bindaddr = lrtr_strdup(config->bindaddr);

		if (!ssh_socket->config.bindaddr)
			goto error;

	} else {
		ssh_socket->config.bindaddr = NULL;
	}

	if (config->client_privkey_path) {
		ssh_socket->config.client_privkey_path = lrtr_strdup(config->client_privkey_path);
		if (!ssh_socket->config.client_privkey_path)
			goto error;

	} else {
		ssh_socket->config.client_privkey_path = NULL;
	}

	if (config->server_hostkey_path) {
		ssh_socket->config.server_hostkey_path = lrtr_strdup(config->server_hostkey_path);

		if (!ssh_socket->config.client_privkey_path)
			goto error;

	} else {
		ssh_socket->config.server_hostkey_path = NULL;
	}

	if (config->connect_timeout == 0)
		ssh_socket->config.connect_timeout = RTRLIB_TRANSPORT_CONNECT_TIMEOUT_DEFAULT;
	else
		ssh_socket->config.connect_timeout = config->connect_timeout;

	if (config->password) {
		ssh_socket->config.password = lrtr_strdup(config->password);

		if (!ssh_socket->config.password)
			goto error;

	} else {
		ssh_socket->config.password = NULL;
	}

	ssh_socket->ident = NULL;
	ssh_socket->config.data = config->data;
	ssh_socket->config.new_socket = config->new_socket;
	ssh_socket->connect_state = CONNECT_INIT;

	return TR_SUCCESS;

error:
	if (ssh_socket->config.host)
		free(ssh_socket->config.host);

	if (ssh_socket->config.username)
		free(ssh_socket->config.username);

	if (ssh_socket->config.bindaddr)
		free(ssh_socket->config.bindaddr);

	if (ssh_socket->config.client_privkey_path)
		free(ssh_socket->config.client_privkey_path);

	if (ssh_socket->config.server_hostkey_path)
		free(ssh_socket->config.server_hostkey_path);

	if (ssh_socket->config.password)
		free(ssh_socket->config.password);

	return TR_ERROR;
}
