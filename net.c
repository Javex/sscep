
/*
 * sscep -- Simple SCEP client implementation
 * Copyright (c) Jarkko Turkulainen 2003. All rights reserved.
 * See the file COPYRIGHT for licensing information.
 */


/* HTTP routine */


#include "sscep.h"

#ifdef WIN32
void perror_w32 (const char *message)
{
    char buffer[BUFSIZ];

    /* letzten Fehlertext holen und formatieren */
    FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, 0, GetLastError(), 0, (LPWSTR) buffer,
		  sizeof buffer, NULL);
    fprintf(stderr, "%s: %s", message, buffer);
}

#define perror perror_w32

#endif

size_t scep_recieve_data(void *buffer, size_t size, size_t nmemb, void *userp)
{
	size_t realsize = size * nmemb;
	struct http_reply *reply = (struct http_reply *)userp;

	reply->payload= realloc(reply->payload, reply->bytes + realsize + 1);
	if(reply->payload == NULL) {
		printf("Not enough memory for HTTP data. Aborting\n");
		return 0;
	}

	memcpy(&(reply->payload[reply->bytes]), buffer, realsize);
	reply->bytes += realsize;
	reply->payload[reply->bytes] = 0;
	return realsize;
}

struct http_reply *scep_send_request(struct http_request *request)
{
	int url_length;
	CURL *curl_handle;
	struct http_reply *reply;
	char *content_type;

	// compute the amount of space that needs to be allocated for the URL.
	url_length = strlen(request->host_name)
				 + strlen(":")
				 + strlen(request->port_str)
				 + (p_flag ? 0 : 1)
				 + strlen(request->path)
				 + strlen(i_char)
				 + (M_flag ? strlen(M_char) : 0)
				 + strlen(request->opstr)
				 + 1;
	request->full_url = malloc(url_length);
	// first insert all chars that are always used
	snprintf(request->full_url, url_length, "%s:%s%s%s?operation=%s&message=%s",
			request->host_name, request->port_str, p_flag ? "" : "/",
			request->path, request->opstr, i_char);

	// insert possible optional additional parameters
	if(M_flag) {
		strncat(request->full_url, "&", 1);
		strncat(request->full_url, M_char, strlen(M_char));
	}

	printf("%s: requesting CA certificate\n", pname);

	if(d_flag)
		printf("Sending request to %s\n", request->full_url);

	curl_handle = curl_easy_init();
	if(!curl_handle) {
		fprintf(stderr, "%s: Could not get CURL handle!\n", pname);
		exit(SCEP_PKISTATUS_NET);
	}
	//
	reply = malloc(sizeof(struct http_reply));
	reply->payload = NULL;
	reply->bytes = 0;
	curl_easy_setopt(curl_handle, CURLOPT_URL, request->full_url);
	// curl makes a copy, so we can free it directly
	free(request->full_url);
	curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, scep_recieve_data);
	curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, reply);

	if(d_flag)
		curl_easy_setopt(curl_handle, CURLOPT_VERBOSE, 1);

	CURLcode res = curl_easy_perform(curl_handle);
	if(res != CURLE_OK) {
		printf("Error! %s\n", curl_easy_strerror(res));
		exit(SCEP_PKISTATUS_NET);
	}



	curl_easy_getinfo(curl_handle, CURLINFO_RESPONSE_CODE, &(reply->status));
	printf("Server responded with status %ld\n", reply->status);

	res = curl_easy_getinfo(curl_handle, CURLINFO_CONTENT_TYPE, &content_type);
	if(res != CURLE_OK) {
		printf("Error while retrieving Content-Type header:\n%s\n", curl_easy_strerror(res));
		exit(SCEP_PKISTATUS_NET);
	}
	if(!content_type) {
		printf("Server did not return a Content-Type.\n");
		exit(SCEP_PKISTATUS_NET);
	}

	if(strcmp(content_type, MIME_GETCA) == 0)
		reply->type = SCEP_MIME_GETCA;
	else if (strcmp(content_type, MIME_GETCA_RA) == 0)
		reply->type = SCEP_MIME_GETCA_RA;
	else if(strcmp(content_type, MIME_GETNEXTCA) == 0)
		reply->type = SCEP_MIME_GETNEXTCA;
	else {
		fprintf(stderr, "%s: wrong MIME content type: %s\n", pname, content_type);
		exit(SCEP_PKISTATUS_NET);
	}

	if (v_flag)
		printf("%s: MIME header: %s\n", pname, content_type);

	curl_easy_cleanup(curl_handle);

	return reply;
}

int scep_operation_getca(struct http_request *request)
{
	int c;
	BIO *bp;
	unsigned int n;
	unsigned char md[EVP_MAX_MD_SIZE];
	FILE *fp;
	struct http_reply *reply;

	if (v_flag)
		fprintf(stdout, "%s: SCEP_OPERATION_GETCA\n",
			pname);

	/* Set CA identifier */
	if (!i_flag)
		i_char = CA_IDENTIFIER;

	/* Forge the HTTP message */

	request->opstr = "GetCACert";
	reply = scep_send_request(request);

	if (reply->payload == NULL) {
		fprintf(stderr, "%s: no data, perhaps you "
		   "should define CA identifier (-i)\n", pname);
		exit (SCEP_PKISTATUS_SUCCESS);
	}
	printf("%s: valid response from server\n", pname);
	if (reply->type == SCEP_MIME_GETCA_RA) {
		/* XXXXXXXXXXXXXXXXXXXXX chain not verified */
		write_ca_ra(reply);
	}
	/* Read payload as DER X.509 object: */
	bp = BIO_new_mem_buf(reply->payload, reply->bytes);
	cacert = d2i_X509_bio(bp, NULL);

	/* Read and print certificate information */
	if (!X509_digest(cacert, fp_alg, md, &n)) {
		ERR_print_errors_fp(stderr);
		exit (SCEP_PKISTATUS_ERROR);
	}
	printf("%s: %s fingerprint: ", pname,
		OBJ_nid2sn(EVP_MD_type(fp_alg)));
	for (c = 0; c < (int)n; c++) {
		printf("%02X%c",md[c],
			(c + 1 == (int)n) ?'\n':':');
	}

	/* Write PEM-formatted file: */
	#ifdef WIN32
	if ((fopen_s(&fp, c_char, "w")))
	#else
	if (!(fp = fopen(c_char, "w")))
	#endif
	{
		fprintf(stderr, "%s: cannot open CA file for "
			"writing\n", pname);
		exit (SCEP_PKISTATUS_ERROR);
	}
	if (PEM_write_X509(fp, cacert) != 1) {
		fprintf(stderr, "%s: error while writing CA "
			"file\n", pname);
		ERR_print_errors_fp(stderr);
		exit (SCEP_PKISTATUS_ERROR);
	}
	printf("%s: CA certificate written as %s\n",
		pname, c_char);
	(void)fclose(fp);
	return SCEP_PKISTATUS_SUCCESS;
}

int scep_operation_getnextca(struct http_request *request)
{
	struct http_reply *reply;
	struct scep scep_t;
	PKCS7 p7;
	STACK_OF(X509) *nextcara = NULL;
	int i;
	X509 *cert = NULL;
	FILE *fp = NULL;

	if (v_flag)
		fprintf(stdout, "%s: SCEP_OPERATION_GETNEXTCA\n",
			pname);

	/* Set CA identifier */
	if (!i_flag)
		i_char = CA_IDENTIFIER;

	/* Forge the HTTP message */

	request->opstr = "GetNextCACert";
	reply = scep_send_request(request);

	if (reply->payload == NULL) {
		fprintf(stderr, "%s: no data, perhaps you "
		   "there is no nextCA available\n", pname);
		exit (SCEP_PKISTATUS_SUCCESS);
	}

	printf("%s: valid response from server\n", pname);

	if (reply->type == SCEP_MIME_GETNEXTCA) {
		/* XXXXXXXXXXXXXXXXXXXXX chain not verified */

		//write_ca_ra(&reply);

		/* Set the whole struct as 0 */
		memset(&scep_t, 0, sizeof(scep_t));

		scep_t.reply_payload = reply.payload;
		scep_t.reply_len = reply.bytes;
		scep_t.request_type = SCEP_MIME_GETNEXTCA;

		pkcs7_verify_unwrap(&scep_t , C_char);

		//pkcs7_unwrap(&scep_t);
	}


	/* Get certs */
	p7 = *(scep_t.reply_p7);
	nextcara = scep_t.reply_p7->d.sign->cert;

	if (v_flag) {
		printf ("verify and unwrap: found %d cert(s)\n", sk_X509_num(nextcara));
		}

	for (i = 0; i < sk_X509_num(nextcara); i++) {
			char buffer[1024];
			char name[1024];
			memset(buffer, 0, 1024);
			memset(name, 0, 1024);

			cert = sk_X509_value(nextcara, i);
			if (v_flag) {
				printf("%s: found certificate with\n"
					"  subject: '%s'\n", pname,
					X509_NAME_oneline(X509_get_subject_name(cert),
						buffer, sizeof(buffer)));
				printf("  issuer: %s\n",
					X509_NAME_oneline(X509_get_issuer_name(cert),
						buffer, sizeof(buffer)));
			}

			/* Create name */
			snprintf(name, 1024, "%s-%d", c_char, i);


			/* Write PEM-formatted file: */
			if (!(fp = fopen(name, "w"))) {
				fprintf(stderr, "%s: cannot open cert file for writing\n",
						pname);
				exit (SCEP_PKISTATUS_FILE);
			}
			if (v_flag)
				printf("%s: writing cert\n", pname);
			if (d_flag)
				PEM_write_X509(stdout, cert);
			if (PEM_write_X509(fp, cert) != 1) {
				fprintf(stderr, "%s: error while writing certificate "
					"file\n", pname);
				ERR_print_errors_fp(stderr);
				exit (SCEP_PKISTATUS_FILE);
			}
			printf("%s: certificate written as %s\n", pname, name);
			(void)fclose(fp);
	}



	return SCEP_PKISTATUS_SUCCESS;
}

int
send_msg(struct http_reply *http,char *msg,char *host,int port,int operation) {
	int			sd, rc, used, bytes;
	struct sockaddr_in	localAddr, servAddr;
	struct hostent		*h;
	char			tmp[1024], *buf, *p;

#ifdef WIN32
	int tv=timeout*1000;
#else
	struct timeval tv;
	tv.tv_sec = timeout;
	tv.tv_usec = 0;
#endif

	/* resolve name */
	h = gethostbyname(host);
	if (h == NULL) {
		printf("unknown host '%s'\n", host);
		return (1);
	}

	/* fill in server socket structure: */
	servAddr.sin_family = h->h_addrtype;
	memcpy((char *) &servAddr.sin_addr.s_addr,
		h->h_addr_list[0], h->h_length);
	servAddr.sin_port = htons(port);

	/* create socket */
	sd = socket(AF_INET, SOCK_STREAM, 0);
	if (sd < 0) {
		perror("cannot open socket ");
		return (1);
	}
	/* bind any port number */
	localAddr.sin_family = AF_INET;
	localAddr.sin_addr.s_addr = htonl(INADDR_ANY);
	localAddr.sin_port = htons(0);
	rc = bind(sd, (struct sockaddr *) &localAddr, sizeof(localAddr));
	if (rc < 0) {
		printf("cannot bind port TCP %u\n", port);
		perror("error ");
		return (1);
	}

	/* connect to server */
	/* The two socket options SO_RCVTIMEO and SO_SNDTIMEO do not work with connect
	   connect has a default timeout of 120 */
	rc = connect(sd, (struct sockaddr *) &servAddr, sizeof(servAddr));
	if (rc < 0) {
		perror("cannot connect");
		return (1);
	}
	setsockopt(sd,SOL_SOCKET, SO_RCVTIMEO,(void *)&tv, sizeof(tv));
	setsockopt(sd,SOL_SOCKET, SO_SNDTIMEO,(void *)&tv, sizeof(tv));
	/* send data */
	rc = send(sd, msg,strlen(msg), 0);

	if (rc < 0) {
		perror("cannot send data ");
		close(sd);
		return (1);
	}
	else if(rc != strlen(msg))
	{
		fprintf(stderr,"incomplete send\n");
		close(sd);
		return (1);
	}

	/* Get response */
	buf = (char *)malloc(1024);
        used = 0;
        while ((bytes = recv(sd,&buf[used],1024,0)) > 0) {
                used += bytes;
                buf = (char *)realloc(buf, used + 1024);
	}
	if (bytes < 0) {
		perror("error receiving data ");
		close(sd);
		return (1);
	}
        buf[used] = '\0';


	/* Fetch the status code: */
	#ifdef WIN32
	sscanf(buf, "%s %ld ", tmp, &http->status);
	#else
	sscanf(buf, "%s %ld ", tmp, &http->status);
	#endif
	if (v_flag)
		fprintf(stdout, "%s: server returned status code %ld\n",
			pname, http->status);

	/* Set SCEP reply type */
	switch (operation) {
		case SCEP_OPERATION_GETCA:
			if (strstr(buf, MIME_GETCA)) {
				http->type = SCEP_MIME_GETCA;
				if (v_flag)
					printf("%s: MIME header: %s\n",
						pname, MIME_GETCA);
			} else if (strstr(buf, MIME_GETCA_RA) ||
				strstr(buf, MIME_GETCA_RA_ENTRUST)) {
				http->type = SCEP_MIME_GETCA_RA;
				if (v_flag)
					printf("%s: MIME header: %s\n",
						pname, MIME_GETCA_RA);
			} else {
				if (v_flag)
					printf("%s: mime_err: %s\n", pname,buf);

				goto mime_err;
			}
			break;
		case SCEP_OPERATION_GETNEXTCA:
			if (strstr(buf, MIME_GETNEXTCA)) {
				http->type = SCEP_MIME_GETNEXTCA;
				if (v_flag)
					printf("%s: MIME header: %s\n",
						pname, MIME_GETNEXTCA);
			}else {
				if (v_flag)
					printf("%s: mime_err: %s\n", pname,buf);

				goto mime_err;
			}
			break;
		default:
			if (!strstr(buf, MIME_PKI)) {
				if (v_flag)
					printf("%s: mime_err: %s\n", pname,buf);
				goto mime_err;
			}
			http->type = SCEP_MIME_PKI;
			if (v_flag)
				printf("%s: MIME header: %s\n",pname,MIME_PKI);
			break;
	}

	/* Find payload */
	for (p = buf; *buf; buf++) {
		if (!strncmp(buf, "\n\n", 2) && *(buf + 2)) {
			http->payload = buf + 2;
			break;
		}
		if (!strncmp(buf, "\n\r\n\r", 4) && *(buf + 4)) {
			http->payload = buf + 4;
			break;
		}
		if (!strncmp(buf, "\r\n\r\n", 4) && *(buf + 4)) {
			http->payload = buf + 4;
			break;
		}
	}
	http->bytes = used - (http->payload - p);
	if (http->payload == NULL) {
		/* This is not necessarily error...
		 * XXXXXXXXXXXXXXXX check */
		fprintf(stderr, "%s: cannot find data from http reply\n",pname);
	}

#ifdef WIN32
	closesocket(sd);
#else
	close(sd);
#endif
	return (0);

mime_err:
	fprintf(stderr, "%s: wrong (or missing) MIME content type\n", pname);
	return (1);

}

/* URL-encode the input and return back encoded string */
char * url_encode(char *s, size_t n) {
	char	*r;
	size_t	len;
	unsigned int     i;
	char    ch[2];

	/* Allocate 2 times bigger space than the original string */
	len = 2 * n;
	r = (char *)malloc(len);
	if (r == NULL) {
		return NULL;
	}
#ifdef WIN32
	strcpy_s(r, sizeof(r), "");
#else
	strcpy(r, "");
#endif

	/* Copy data */
	for (i = 0; i < n; i++) {
		switch (*(s+i)) {
			case '+':
#ifdef WIN32
				//strncat_s(r, sizeof(r), "%2B", len);
				strncat(r, "%2B", len);
#else
				strncat(r, "%2B", len);
#endif
				break;
			case '-':
#ifdef WIN32
				//strncat_s(r, sizeof(r), "%2D", len);
				strncat(r, "%2D", len);
#else
				strncat(r, "%2D", len);
#endif
				break;
			case '=':
#ifdef WIN32
				//strncat_s(r, sizeof(r), "%3D", len);
				strncat(r, "%3D", len);
#else
				strncat(r, "%3D", len);
#endif
				break;
			case '\n':
#ifdef WIN32
				//strncat_s(r, sizeof(r), "%0A", len);
				strncat(r, "%0A", len);
#else
				strncat(r, "%0A", len);
#endif
				break;
			default:
				ch[0] = *(s+i);
				ch[1] = '\0';
#ifdef WIN32
				//strncat_s(r, sizeof(r), ch, len);
				strncat(r, ch, len);
#else
				strncat(r, ch, len);
#endif
				break;
		}
	}
	r[len-1] = '\0';
	return r;
}
