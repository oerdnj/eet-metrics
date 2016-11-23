/* This example code is placed in the public domain. */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netdb.h>
#include <errno.h>
#include <time.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>

#define MAX_BUF 1024000
#define CAFILE "/etc/ssl/certs/ca-certificates.crt"

#define MSG_POST "POST /eet/services/EETServiceSOAP/v3 HTTP/1.1"
#define MSG_EOL "\r\n"
#define MSG_HOST "Host: "
#define MSG_CONTENT_TYPE "Content-Type: application/soap+xml; charset=utf-8"
#define MSG_CONTENT_LENGTH "Content-Length: "

#define stamp(var) time_t time_##var; time(&time_##var);

static inline long get_time(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (long)ts.tv_sec * 1000000000L + ts.tv_nsec;
}

#define diff(name) ((name ## _stop - name ## _start ) / 1000000000L), ((( name ## _stop - name ## _start ) % 1000000000L))

#define CAFILE "/etc/ssl/certs/ca-certificates.crt"

#define CHECK(x)						  \
	if ((r = x) < 0) {					  \
		fprintf(stderr, #x ": %s\n", gnutls_strerror(r)); \
		exit(EXIT_FAILURE);				  \
	}

static int _verify_certificate_callback(gnutls_session_t session);

int main(int argc, char **argv) {
	struct addrinfo hints;
	struct addrinfo *result, *rp;
        gnutls_certificate_credentials_t xcred;
        gnutls_session_t session4, session6;
	int r;
	int fd;
	char sendbuf[MAX_BUF], recvbuf[MAX_BUF];
	ssize_t sendbuf_len, recvbuf_len;
	char len_buf[16];

	if (argc == 1) {
		printf("%15s,%15s,%15s,%15s,%15s,%15s,%15s,%15s,%15s,%15s,%15s,%15s,%15s\n", "getaddrinfo", "connect4", "tls_handshake4", "tls_send4", "tls_recv4", "tls_bye4", "close4", "connect6", "tls_handshake6", "tls_send6", "tls_recv6", "tls_bye6", "close6");
		exit(0);
	}
	
	if (argc != 5) {
		fprintf(stderr, "Usage: %s host port message4_file message6_file ...\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	if (gnutls_check_version("3.1.4") == NULL) {
		fprintf(stderr, "GnutTLS 3.1.4 or later is required for this example\n");
		exit(EXIT_FAILURE);
	}

	CHECK(gnutls_global_init());
	CHECK(gnutls_certificate_allocate_credentials(&xcred));
        CHECK(gnutls_certificate_set_x509_trust_file(xcred, CAFILE, GNUTLS_X509_FMT_PEM));
        gnutls_certificate_set_verify_function(xcred, _verify_certificate_callback);
	
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	long gai_start = get_time();

	int s = getaddrinfo(argv[1], argv[2], &hints, &result);

	long gai_stop = get_time();
	
	if (s != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
		exit(EXIT_FAILURE);
	}

	long connect4_start, connect4_stop;
	int sock4;
	for (rp = result; rp != NULL; rp = rp->ai_next) {
		if (rp->ai_family != AF_INET) {
			continue;
		}
		
		if ((sock4 = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol)) < 0) {
			fprintf(stderr, "socket: %s\n", strerror(errno));
			exit(EXIT_FAILURE);
		}

		connect4_start = get_time();
		r = connect(sock4, rp->ai_addr, rp->ai_addrlen);
		connect4_stop = get_time();

		if (r < 0) {
			fprintf(stderr, "connect4: %s...\n", strerror(errno));
			exit(EXIT_FAILURE);
		}
	}
	if (sock4 == 0) {
		fprintf(stderr, "connect: no IPv4 address provided\n");
		exit(EXIT_FAILURE);
	}

        CHECK(gnutls_init(&session4, GNUTLS_CLIENT));

	gnutls_session_set_ptr(session4, (void *) argv[1]);
        gnutls_server_name_set(session4, GNUTLS_NAME_DNS, argv[1],
                               strlen(argv[1]));

        CHECK(gnutls_set_default_priority(session4));

        /* put the x509 credentials to the current session
         */
        CHECK(gnutls_credentials_set(session4, GNUTLS_CRD_CERTIFICATE, xcred));
	
        gnutls_transport_set_int(session4, sock4);
        gnutls_handshake_set_timeout(session4,
                                     GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);

	long tls_handshake4_start = get_time();
        do {
                r = gnutls_handshake(session4);
        }
        while (r < 0 && gnutls_error_is_fatal(r) == 0);
	long tls_handshake4_stop = get_time();	

	if (r < 0) {
		fprintf(stderr, "gnutls_handshake(session4): %s\n", gnutls_strerror(r));
		exit(EXIT_FAILURE);
	}

	if ((fd = open(argv[3], O_RDONLY)) < 0) {
		fprintf(stderr, "open: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	if ((sendbuf_len = read(fd, sendbuf, sizeof(sendbuf) - 1)) < 0) {
		fprintf(stderr, "read: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
	sendbuf[sendbuf_len] = 0;

	if (close(fd) < 0) {
		fprintf(stderr, "close: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	gnutls_record_cork(session4);

	snprintf(len_buf, sizeof(len_buf), "%d", sendbuf_len);
	
	CHECK(gnutls_record_send(session4, MSG_POST, strlen(MSG_POST)));
	CHECK(gnutls_record_send(session4, MSG_EOL, strlen(MSG_EOL)));
	CHECK(gnutls_record_send(session4, MSG_HOST, strlen(MSG_HOST)));
	CHECK(gnutls_record_send(session4, argv[1], strlen(argv[1])));
	CHECK(gnutls_record_send(session4, MSG_EOL, strlen(MSG_EOL)));
	CHECK(gnutls_record_send(session4, MSG_CONTENT_TYPE, strlen(MSG_CONTENT_TYPE)));
	CHECK(gnutls_record_send(session4, MSG_EOL, strlen(MSG_EOL)));
	CHECK(gnutls_record_send(session4, MSG_CONTENT_LENGTH, strlen(MSG_CONTENT_LENGTH)));
	CHECK(gnutls_record_send(session4, len_buf, strlen(len_buf)));
	CHECK(gnutls_record_send(session4, MSG_EOL, strlen(MSG_EOL)));
	CHECK(gnutls_record_send(session4, MSG_EOL, strlen(MSG_EOL)));

	CHECK(gnutls_record_send(session4, sendbuf, sendbuf_len));

	long tls_send4_start = get_time();
	CHECK(gnutls_record_uncork(session4, GNUTLS_RECORD_WAIT));
	long tls_send4_stop = get_time();

	long tls_recv4_start = get_time();
	r = gnutls_record_recv(session4, recvbuf, sizeof(recvbuf) - 1);
	long tls_recv4_stop = get_time();

	if (r == 0) {
		fprintf(stderr, "gnutls_record_recv(session4, ...): peer has closed TLS connection\n");
		exit(EXIT_FAILURE);
	} else if (r < 0) {
		fprintf(stderr, "gnutls_record_recv(session4, ...): %s, %s\n", gnutls_strerror(r), strerror(errno));
		exit(EXIT_FAILURE);
	}

	recvbuf[r] = 0;
	/*	printf("%s\n", recvbuf); */
	
	long tls_bye4_start = get_time();
        CHECK(gnutls_bye(session4, GNUTLS_SHUT_RDWR));
	long tls_bye4_stop = get_time();

        gnutls_deinit(session4);
	
	long close4_start = get_time();
	if (shutdown(sock4, SHUT_RDWR) < 0) {
		fprintf(stderr, "shutdown: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
	if (close(sock4) < 0) {
		fprintf(stderr, "close: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
	long close4_stop = get_time();

	/* IPv6 */

	long connect6_start, connect6_stop;
	int sock6;
	for (rp = result; rp != NULL; rp = rp->ai_next) {
		if (rp->ai_family != AF_INET6) {
			continue;
		}
		
		if ((sock6 = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol)) < 0) {
			fprintf(stderr, "socket: %s\n", strerror(errno));
			exit(EXIT_FAILURE);
		}

		connect6_start = get_time();
		if (connect(sock6, rp->ai_addr, rp->ai_addrlen) < 0) {
			fprintf(stderr, "connect: %s...\n", strerror(errno));
			exit(EXIT_FAILURE);
		}
		connect6_stop = get_time();
	}
	if (sock6 == 0) {
		fprintf(stderr, "connect6: no IPv6 address provided\n");
		exit(EXIT_FAILURE);
	}

	CHECK(gnutls_init(&session6, GNUTLS_CLIENT));

	gnutls_session_set_ptr(session6, (void *) argv[1]);
        gnutls_server_name_set(session6, GNUTLS_NAME_DNS, argv[1],
                               strlen(argv[1]));

        CHECK(gnutls_set_default_priority(session6));

        /* put the x509 credentials to the current session
         */
        CHECK(gnutls_credentials_set(session6, GNUTLS_CRD_CERTIFICATE, xcred));

        gnutls_transport_set_int(session6, sock6);
        gnutls_handshake_set_timeout(session6,
                                     GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);

	long tls_handshake6_start = get_time();
        do {
                r = gnutls_handshake(session6);
        }
        while (r < 0 && gnutls_error_is_fatal(r) == 0);
	long tls_handshake6_stop = get_time();

	if (r < 0) {
		fprintf(stderr, "gnutls_handshake(session6): %s\n", gnutls_strerror(r));
		exit(EXIT_FAILURE);
	}

	if ((fd = open(argv[4], O_RDONLY)) < 0) {
		fprintf(stderr, "open: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	if ((sendbuf_len = read(fd, sendbuf, sizeof(sendbuf))) < 0) {
		fprintf(stderr, "read: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (close(fd) < 0) {
		fprintf(stderr, "close: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	snprintf(len_buf, sizeof(len_buf), "%d", sendbuf_len);

	gnutls_record_cork(session6);

	CHECK(gnutls_record_send(session6, MSG_POST, strlen(MSG_POST)));
	CHECK(gnutls_record_send(session6, MSG_EOL, strlen(MSG_EOL)));
	CHECK(gnutls_record_send(session6, MSG_HOST, strlen(MSG_HOST)));
	CHECK(gnutls_record_send(session6, argv[1], strlen(argv[1])));
	CHECK(gnutls_record_send(session6, MSG_EOL, strlen(MSG_EOL)));
	CHECK(gnutls_record_send(session6, MSG_CONTENT_TYPE, strlen(MSG_CONTENT_TYPE)));
	CHECK(gnutls_record_send(session6, MSG_EOL, strlen(MSG_EOL)));
	CHECK(gnutls_record_send(session6, MSG_CONTENT_LENGTH, strlen(MSG_CONTENT_LENGTH)));
	CHECK(gnutls_record_send(session6, len_buf, strlen(len_buf)));
	CHECK(gnutls_record_send(session6, MSG_EOL, strlen(MSG_EOL)));
	CHECK(gnutls_record_send(session6, MSG_EOL, strlen(MSG_EOL)));

	CHECK(gnutls_record_send(session6, sendbuf, sendbuf_len));

	long tls_send6_start = get_time();
	CHECK(gnutls_record_uncork(session6, GNUTLS_RECORD_WAIT));
	long tls_send6_stop = get_time();

	long tls_recv6_start = get_time();
	r = gnutls_record_recv(session6, recvbuf, sizeof(recvbuf) - 1);
	long tls_recv6_stop = get_time();
	
	if (r == 0) {
		fprintf(stderr, "gnutls_record_recv(session6, ...): peer has closed TLS connection\n");
		exit(EXIT_FAILURE);
	} else if (r < 0) {
		fprintf(stderr, "gnutls_record_recv(session6, ...): %s\n", gnutls_strerror(r));
		exit(EXIT_FAILURE);
	}

	recvbuf[r] = 0;

	long tls_bye6_start = get_time();
        CHECK(gnutls_bye(session6, GNUTLS_SHUT_RDWR));
	long tls_bye6_stop = get_time();

	gnutls_deinit(session6);
	
	long close6_start = get_time();
	if (shutdown(sock6, SHUT_RDWR) < 0) {
		fprintf(stderr, "shutdown: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
	if (close(sock6) < 0) {
		fprintf(stderr, "close: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
	long close6_stop = get_time();
	
        gnutls_certificate_free_credentials(xcred);
        gnutls_global_deinit();
	
	printf("%4ld.%010ld,%4ld.%010ld,%4ld.%010ld,%4ld.%010ld,%4ld.%010ld,%4ld.%010ld,%4ld.%010ld,%4ld.%010ld,%4ld.%010ld,%4ld.%010ld,%4ld.%010ld,%4ld.%010ld,%4ld.%010ld\n", diff(gai), diff(connect4), diff(tls_handshake4), diff(tls_send4), diff(tls_recv4), diff(tls_bye4), diff(close4), diff(connect6), diff(tls_handshake6), diff(tls_send6), diff(tls_recv6), diff(tls_bye6), diff(close6));
	
	return(0);
}

/* This function will verify the peer's certificate, and check
 * if the hostname matches, as well as the activation, expiration dates.
 */
static int _verify_certificate_callback(gnutls_session_t session)
{
        unsigned int status;
        int type;
        const char *hostname;
        gnutls_datum_t out;
	int r;

        /* read hostname */
        hostname = gnutls_session_get_ptr(session);

        /* This verification function uses the trusted CAs in the credentials
         * structure. So you must have installed one or more CA certificates.
         */

        CHECK(gnutls_certificate_verify_peers3(session, hostname,
					       &status));

        type = gnutls_certificate_type_get(session);

        CHECK(gnutls_certificate_verification_status_print(status, type,
                                                           &out, 0));

//        printf("%s", out.data);

        gnutls_free(out.data);

        if (status != 0) {
		/* Certificate is not trusted */
                return GNUTLS_E_CERTIFICATE_ERROR;
	}

        /* notify gnutls to continue handshake normally */
        return 0;
}
