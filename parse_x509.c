
#include <tls.h>
#include <tls_internal.h>

#include <sys/stat.h>
#include <ctype.h>
#include <err.h>
#include <mbuf.h>

#include <openssl/x509.h>
#include <openssl/pem.h>

#include <zlib.h>

static int total, nfailed;

static void cleandir(char *fn)
{
	int i;
	for (i = 0; fn[i]; i++) {
		if (fn[i] == ':' || fn[i] == ' ')
			fn[i] = '-';
	}
}

static void dump_failed(const char *sig, const char *data, const char *errmsg)
{
	char fn[256];
	FILE *f;

	if (!errmsg)
		errmsg = "(null)";
	
	mkdir("failed", 0700);

	if (1) {
		if (strstr(errmsg, "invalid commonName: ")
		    || strstr(errmsg, "invalid countryName: ")
		    || strstr(errmsg, "invalid stateName: ")
		    || strstr(errmsg, "invalid localityName: ")
		    || strstr(errmsg, "invalid streetAddress: ")
		    || strstr(errmsg, "invalid organizationName: ")
		    || strstr(errmsg, "invalid organizationalUnitName: ")
		    || strstr(errmsg, "invalid dns: ")
		    || strstr(errmsg, "invalid email: ")
		    || strstr(errmsg, "invalid uri: "))
		{
			errmsg = strchr(errmsg, ':') + 2;
		}
		snprintf(fn, sizeof fn, "failed/%s", errmsg);
		cleandir(fn);
		mkdir(fn, 0700);
		snprintf(fn, sizeof fn, "failed/%s/%s.crt", errmsg, sig);
		cleandir(fn);
		printf("  %s\n", fn);
	} else {
		snprintf(fn, sizeof fn, "failed/%s.crt", sig);
		printf("  %s - %s\n", fn, errmsg);
	}
	f = fopen(fn, "wb");
	if (!f)
		err(1, "fopen: %s", fn);
	fprintf(f, "%s\n%s\n", data, errmsg);
	fclose(f);
}

static void parse_pem(const char *sig, const char *data, size_t datalen)
{
	BIO *bio;
	X509 *x509;
	struct tls *ctx;
	struct tls_cert *cert = NULL;
	int e;

	ctx = tls_client();
	if (!ctx)
		err(1, "tls_client");
	bio = BIO_new_mem_buf((char *)data, datalen);
	if (!bio)
		errx(1, "BIO_new_mem_buf");

	x509 = PEM_read_bio_X509(bio, NULL, NULL, NULL);
	if (!x509) {
		tls_set_error_libssl(ctx, "X509 parse failed");
		e = -1;
	} else {
		e = tls_parse_cert(ctx, &cert, NULL, x509);
	}

	if (e == 0) {
		tls_cert_free(cert);
	} else if (sig) {
		dump_failed(sig, data, tls_error(ctx));
		nfailed++;
	} else {
		printf("FAIL: %s\n", tls_error(ctx));
		nfailed++;
	}
	X509_free(x509);
	BIO_free(bio);
	tls_free(ctx);
	total++;
}

static void parse_line(char *ln, size_t lnsize)
{
	bool ok;
	char *src;
	struct MBuf pem;
	size_t n;
	const char *pfx = "-----BEGIN CERTIFICATE-----\n";
	const char *sfx = "-----END CERTIFICATE-----\n";

	src = memchr(ln, ',', lnsize);
	if (!src) {
		printf("bad line\n");
		return;
	}
	*src++ = 0;
	lnsize -= src - ln;
	mbuf_init_dynamic(&pem);
	ok = mbuf_write(&pem, pfx, strlen(pfx));
	if (!ok)
		errx(1, "mbuf_write");
	while (lnsize > 0) {
		n = (lnsize > 64) ? 64 : lnsize;
		ok = mbuf_write(&pem, src, n);
		if (!ok)
			errx(1, "mbuf_write");
		ok = mbuf_write_byte(&pem, '\n');
		if (!ok)
			errx(1, "mbuf_write_byte");
		src += n;
		lnsize -= n;
	}
	ok = mbuf_write(&pem, sfx, strlen(sfx));
	if (!ok)
		errx(1, "mbuf_write");

	ok = mbuf_write_byte(&pem, 0);
	if (!ok)
		errx(1, "mbuf_write_byte");

	parse_pem(ln, mbuf_data(&pem), mbuf_written(&pem) - 1);

	mbuf_free(&pem);
}

static void parse_gzfile(const char *fn)
{
	ssize_t res;
	int count = 0;
	gzFile gz;
	char buf[32768];
	int old_failed = nfailed;

	printf("Processing %s\n", fn);

	gz = gzopen(fn, "rb");
	if (!gz)
		err(1, "gzdopen");

	for (;;) {
		if (!gzgets(gz, buf, sizeof buf))
			break;
		res = strlen(buf);
		while (res > 0 && isspace(buf[res-1]))
			res--;
		if (!res)
			continue;
		parse_line(buf, res);
		count++;
	}
	gzclose(gz);
	if (nfailed != old_failed) {
		printf("%d certs, %d failed\n", count, nfailed - old_failed);
	} else {
		printf("%d certs\n", count);
	}
}

static void parse_cert_file(const char *fn)
{
	size_t len;
	char *data, *start, *end, *pos;
	data = (char *)tls_load_file(fn, &len, NULL);
	if (!data)
		err(1, "tls_load_file: %s", fn);
	pos = data;
	while (1) {
		start = strstr(pos, "-----BEGIN");
		if (!start)
			break;
		end = strstr(start + 10, "-----END");
		if (end)
			end = strstr(end + 8, "-----");
		if (!end)
			break;
		pos = end + 5;
		parse_pem(NULL, start, pos - start);
	}
	free(data);
}

static void parse_any_file(const char *fn)
{
	const char *ext;

	ext = strrchr(fn, '.');
	if (!ext)
		ext = "";

	if (!strcmp(ext, ".crt") || !strcmp(ext, ".pem")) {
		parse_cert_file(fn);
	} else if (!strcmp(ext, ".gz")){
		parse_gzfile(fn);
	} else {
		warnx("unknown file type: %s", fn);
	}
}

int main(int argc, char *argv[])
{
	int i;

	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);

	if (tls_init() < 0)
		err(1, "tls_init");

	for (i = 1; i < argc; i++)
		parse_any_file(argv[i]);
	printf("total: %d, failed: %d\n", total, nfailed);
	return 0;
}

