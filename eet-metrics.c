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
#include <sys/socket.h>
#include <netdb.h>
#include <errno.h>
#include <time.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>

/* A very basic TLS client, with X.509 authentication and server certificate
 * verification utilizing the GnuTLS 3.1.x API. 
 * Note that error recovery is minimal for simplicity.
 */

#define MAX_BUF 1024
#define CAFILE "/etc/ssl/certs/ca-certificates.crt"
#define MSG "GET / HTTP/1.0\r\n\r\n"

#define stamp(var) time_t time_##var; time(&time_##var);

static inline long get_time(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (long)ts.tv_sec * 1000000000L + ts.tv_nsec;
}

#define diff(name) ((name ## _stop - name ## _start ) / 1000000000L), ((( name ## _stop - name ## _start ) % 1000000000L) / 10000L)

static inline double diff_usec(long start, long stop)
{
}
	

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
        gnutls_session_t session;
	int r;

	if (argc != 4) {
		fprintf(stderr, "Usage: %s host port message...\n", argv[0]);
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

        CHECK(gnutls_init(&session, GNUTLS_CLIENT));

	gnutls_session_set_ptr(session, (void *) argv[1]);
        gnutls_server_name_set(session, GNUTLS_NAME_DNS, argv[1],
                               strlen(argv[1]));

        CHECK(gnutls_set_default_priority(session));

        /* put the x509 credentials to the current session
         */
        CHECK(gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, xcred));
	
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
		if (connect(sock4, rp->ai_addr, rp->ai_addrlen) < 0) {
			fprintf(stderr, "connect: %s...\n", strerror(errno));
			exit(EXIT_FAILURE);
		}
		connect4_stop = get_time();
	}


        gnutls_transport_set_int(session, sock4);
        gnutls_handshake_set_timeout(session,
                                     GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);

	long gnutls_handshake_start = get_time();
        do {
                r = gnutls_handshake(session);
        }
        while (r < 0 && gnutls_error_is_fatal(r) == 0);
	long gnutls_handshake_stop = get_time();	

	if (r < 0) {
		fprintf(stderr, "gnutls_handshke(session): %s\n", gnutls_strerror(r));
	} else {
		char *desc;

                desc = gnutls_session_get_desc(session);
                printf("- Session info: %s\n", desc);
                gnutls_free(desc);
	}

	long gnutls_bye_start = get_time();
        CHECK(gnutls_bye(session, GNUTLS_SHUT_RDWR));
	long gnutls_bye_stop = get_time();
	
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

        gnutls_deinit(session);
        gnutls_certificate_free_credentials(xcred);
        gnutls_global_deinit();

	printf("%14s:%14s:%14s:%14s:%14s\n", "getaddrinfo", "connect4", "close4", "tls_handshake", "tls_bye");
	
	printf("%9ld.%04ld:%9ld.%04ld:%9ld.%04ld:%9ld.%04ld:%9ld.%04ld\n", diff(gai), diff(connect4), diff(close4), diff(gnutls_handshake), diff(gnutls_bye));
	
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

        printf("%s", out.data);

        gnutls_free(out.data);

        if (status != 0) {
		/* Certificate is not trusted */
                return GNUTLS_E_CERTIFICATE_ERROR;
	}

        /* notify gnutls to continue handshake normally */
        return 0;
}
