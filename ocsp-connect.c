
#include <sys/types.h>
#include <stdint.h>
#include <stdbool.h>
#include <err.h>
#include <time.h>
#include "mbuf.h"

#include <tls.h>

#include <curl/curl.h>

#include <openssl/crypto.h>

static void show_time(const char *desc, time_t t)
{
	const char *val;
	val = t ? ctime(&t) : "--\n";
	printf("%s: %s", desc, val);
}

static void show_ocsp_info(const char *desc, struct tls *ctx)
{
	int req_status, cert_status, crl_reason, res;
	const char *msg;
	time_t this_update, next_update, revocation_time;

	res = tls_get_ocsp_info(ctx, &req_status, &cert_status, &crl_reason,
				&this_update, &next_update, &revocation_time,
				&msg);
	printf("%s: %s\n", desc, msg);
	if (res == 0) {
		printf("  req_status=%d cert_status=%d crl_reason=%d\n",
		       req_status, cert_status, crl_reason);
		show_time("  this update", this_update);
		show_time("  next update", next_update);
		show_time("  revocation", revocation_time);
	}
}

static void check_curl(CURL *http, long code, const char *desc)
{
	if (code == CURLE_OK)
		return;
	errx(1, "Curl failure - %s: %s", desc, curl_easy_strerror(code));
}

static size_t write_callback(void *src, size_t size, size_t nmemb, void *arg)
{
	struct MBuf *dst = arg;
	bool ok = mbuf_write(dst, src, size*nmemb);
	if (ok)
		return nmemb;
	return 0;
}

static void check_ocsp(struct tls *target)
{
	struct tls *ocsp = NULL;
	char *ocsp_url;
	void *req_data;
	size_t req_len;
	CURL *http = NULL;
	struct curl_slist *hdrs = NULL;
	struct MBuf response_buf;
	int res, code;
	long rescode = 0;
	char *ctype = NULL;

	mbuf_init_dynamic(&response_buf);

	res = tls_ocsp_check_peer_request(&ocsp, target, &ocsp_url,
					  &req_data, &req_len);
	if (res == TLS_NO_OCSP) {
		printf("Cert has no OCSP\n");
		tls_free(ocsp);
		return;
	}
	printf("OCSP URL: %s\n", ocsp_url);
	if (res != 0) {
		printf("OCSP req build failed: %s\n", tls_error(ocsp));
		tls_free(ocsp);
		return;
	}

	hdrs = curl_slist_append(hdrs, "Content-Type: application/ocsp-request");
	hdrs = curl_slist_append(hdrs, "Accept: application/ocsp-response");

	http = curl_easy_init();
	if (!http)
		errx(1, "curl_easy_init");

	curl_easy_setopt(http, CURLOPT_HTTPHEADER, hdrs);
	curl_easy_setopt(http, CURLOPT_URL, ocsp_url);
	curl_easy_setopt(http, CURLOPT_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);
	curl_easy_setopt(http, CURLOPT_HTTP_CONTENT_DECODING, 0);
	curl_easy_setopt(http, CURLOPT_FOLLOWLOCATION, 0);
	curl_easy_setopt(http, CURLOPT_TCP_NODELAY, 1);
	curl_easy_setopt(http, CURLOPT_POSTFIELDS, req_data);
	curl_easy_setopt(http, CURLOPT_POSTFIELDSIZE, req_len);
	curl_easy_setopt(http, CURLOPT_WRITEFUNCTION, write_callback);
	curl_easy_setopt(http, CURLOPT_WRITEDATA, &response_buf);

	code = curl_easy_perform(http);
	check_curl(http, code, "HTTP request");

	curl_easy_getinfo(http, CURLINFO_CONTENT_TYPE, &ctype);
	curl_easy_getinfo(http, CURLINFO_RESPONSE_CODE, &rescode);

	if (rescode != 200)
		errx(1, "OCSP responder rescode: %ld\n", rescode);
	if (!ctype)
		errx(1, "OCSP responder gave no content-type\n");
	if (strcmp(ctype, "application/ocsp-response") != 0)
		errx(1, "Invalid ctype: %s\n", ctype);

	res = tls_ocsp_process_response(ocsp,
					mbuf_data(&response_buf),
					mbuf_written(&response_buf));
	if (res != 0) {
		printf("tls_ocsp_process_response: %s\n", tls_error(ocsp));
	}
	show_ocsp_info("OCSP responder", ocsp);
	tls_free(ocsp);

	curl_easy_cleanup(http);
	curl_slist_free_all(hdrs);
	mbuf_free(&response_buf);
}

int main(int argc, char *argv[])
{
	struct tls_config *conf;
	struct tls *ctx;
	int res;
	const char *host;

	if (argc < 2)
		errx(1, "give host as arg\n");
	host = argv[1];

	printf("libssl: %s\n", SSLeay_version(SSLEAY_VERSION));
	res = tls_init();
	if (res < 0)
		errx(1, "tls_init");

	res = curl_global_init(CURL_GLOBAL_NOTHING);
	check_curl(NULL, res, "Global Init");

	conf = tls_config_new();
	if (!conf)
		errx(1, "tls_config_new");

	tls_config_set_protocols(conf, TLS_PROTOCOLS_ALL);
	tls_config_set_ciphers(conf, "compat");

	ctx = tls_client();
	if (!ctx)
		errx(1, "tls_client");

	res = tls_configure(ctx, conf);
	if (res < 0)
		errx(1, "tls_configure: %s", tls_error(ctx));

	res = tls_connect(ctx, host, "443");
	if (res < 0)
		errx(1, "tls_connect: %s", tls_error(ctx));

	res = tls_handshake(ctx);
	if (res < 0)
		errx(1, "tls_handshake: %s", tls_error(ctx));

	show_ocsp_info("OCSP stapling", ctx);

	check_ocsp(ctx);

	tls_close(ctx);
	tls_free(ctx);
	tls_config_free(conf);

	curl_global_cleanup();

	return 0;
}

