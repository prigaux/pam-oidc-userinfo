#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <curl/curl.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>

struct response {
    char *ptr;
    size_t len;
};

static size_t writefunc(void *ptr, size_t size, size_t nmemb, struct response *r) {
    size_t data_size = size * nmemb;
    size_t new_len = r->len + data_size;
    char *new_ptr = realloc(r->ptr, new_len + 1);

    if (new_ptr == NULL) {
        syslog(LOG_AUTH|LOG_DEBUG, "pam_oidc_userinfo: memory allocation failed");
        return 0;
    }

    r->ptr = new_ptr;

    memcpy(r->ptr + r->len, ptr, data_size);
    r->ptr[r->len = new_len] = '\0';

    return data_size;
}

static int check_response(const char * response_data, char *mandatory_substr, const char **oneof_substr) {
    if (strstr(response_data, mandatory_substr) == NULL) {
        syslog(LOG_AUTH|LOG_DEBUG, "pam_oauth2: can't find '%s' in the userinfo response %s", mandatory_substr, response_data);
        return PAM_AUTH_ERR;
    }
    if (oneof_substr[0] == NULL) {
        // nothing to check
        return PAM_SUCCESS;
    }

    for (int i = 0; oneof_substr[i] != NULL; i++) {
        if (strstr(response_data, oneof_substr[i]) != NULL) {
            syslog(LOG_AUTH|LOG_DEBUG, "pam_oidc_userinfo: successfully found substring %s in userinfo response", oneof_substr[i]);
            return PAM_SUCCESS;
        }
    }
    // no match
    syslog(LOG_AUTH|LOG_DEBUG, "pam_oidc_userinfo: one of the following substring is mandatory in userinfo response %s", response_data);
    for (int i = 0; oneof_substr[i] != NULL; i++) {
        syslog(LOG_AUTH|LOG_DEBUG, "pam_oidc_userinfo: tried '%s'", oneof_substr[i]);
    }
    return PAM_AUTH_ERR;
}

static int query_token_info(const char * const tokeninfo_url, const char * const authtok, long *response_code, struct response *token_info) {
    int ret = 1;
    struct curl_slist *headers = NULL;
    char *authorization_header;
    CURL *session = curl_easy_init();

    if ((authorization_header = malloc(strlen("Authorization: ") + strlen(authtok) +1))){
        strcpy(authorization_header, "Authorization: ");
        strcat(authorization_header, authtok);
    }else{
        syslog(LOG_AUTH|LOG_DEBUG, "pam_oidc_userinfo: authorization : memory allocation failed");
        return ret;
    }

    if (!session) {
        syslog(LOG_AUTH|LOG_DEBUG, "pam_oidc_userinfo: can't initialize curl");
        return ret;
    }

    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(headers, authorization_header);

    curl_easy_setopt(session, CURLOPT_URL, tokeninfo_url);
    curl_easy_setopt(session, CURLOPT_HTTPHEADER, headers);
    
    syslog(LOG_AUTH|LOG_DEBUG, tokeninfo_url);

    curl_easy_setopt(session, CURLOPT_WRITEFUNCTION, writefunc);
    curl_easy_setopt(session, CURLOPT_WRITEDATA, token_info);

    if (curl_easy_perform(session) == CURLE_OK &&
            curl_easy_getinfo(session, CURLINFO_RESPONSE_CODE, response_code) == CURLE_OK) {
        ret = 0;
    } else {
        syslog(LOG_AUTH|LOG_DEBUG, "pam_oidc_userinfo: failed to perform curl request");
    }

    free(authorization_header);

    curl_easy_cleanup(session);

    return ret;
}

static int authenticate(const char * const tokeninfo_url, const char * const authtok, char *mandatory_substr, const char **oneof_substr) {
    struct response token_info;
    long response_code = 0;
    int ret;

    if ((token_info.ptr = malloc(1)) == NULL) {
        syslog(LOG_AUTH|LOG_DEBUG, "pam_oidc_userinfo: memory allocation failed");
        return PAM_AUTHINFO_UNAVAIL;
    }
    token_info.ptr[token_info.len = 0] = '\0';

    if (query_token_info(tokeninfo_url, authtok, &response_code, &token_info) != 0) {
        ret = PAM_AUTHINFO_UNAVAIL;
    } else if (response_code == 200) {
        ret = check_response(token_info.ptr, mandatory_substr, oneof_substr);
    } else {
        syslog(LOG_AUTH|LOG_DEBUG, "pam_oidc_userinfo: authentication failed with response_code=%li", response_code);
        ret = PAM_AUTH_ERR;
    }

    free(token_info.ptr);

    return ret;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    const char *tokeninfo_url = NULL, *authtok = NULL;

    if (argc > 0) tokeninfo_url = argv[0];

    if (tokeninfo_url == NULL || *tokeninfo_url == '\0') {
        syslog(LOG_AUTH|LOG_DEBUG, "pam_oidc_userinfo: tokeninfo_url is not defined or invalid");
        return PAM_AUTHINFO_UNAVAIL;
    }

    if (argc < 2 || argv[1][0] == '\0') {
        syslog(LOG_AUTH|LOG_DEBUG, "pam_oidc_userinfo: login_field is not defined or empty");
        return PAM_AUTHINFO_UNAVAIL;
    }

    const char *user = NULL;
    if (pam_get_user(pamh, &user, NULL) != PAM_SUCCESS || user == NULL || *user == '\0') {
        syslog(LOG_AUTH|LOG_DEBUG, "pam_oidc_userinfo: can't get user login");
        return PAM_AUTHINFO_UNAVAIL;
    }

    if (pam_get_authtok(pamh, PAM_AUTHTOK, &authtok, NULL) != PAM_SUCCESS || authtok == NULL || *authtok == '\0') {
        syslog(LOG_AUTH|LOG_DEBUG, "pam_oidc_userinfo: can't get authtok");
        return PAM_AUTHINFO_UNAVAIL;
    }

    // Abort if the password doesn't match "Bearer xxxx". This speeds things up and avoid uselessly bothering the OIDC server */
    if (strncmp("Bearer ", authtok, strlen("Bearer ")) != 0) {
        return PAM_AUTH_ERR;
    }

    char *mandatory_substr;
    asprintf(&mandatory_substr, "\"%s\":\"%s\"", argv[1], user);

    const char *oneof_substr[argc-1];
    for (int i = 2; i < argc; ++i) {
        oneof_substr[i-2] = argv[i];
    }
    oneof_substr[argc-2] = NULL;

    int ret = authenticate(tokeninfo_url, authtok, mandatory_substr, oneof_substr);

    free(mandatory_substr);

    if (ret == PAM_SUCCESS) {
        syslog(LOG_AUTH|LOG_DEBUG, "pam_oidc_userinfo: successfully authenticated '%s'", user);
    }
    return ret;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_CRED_UNAVAIL;
}
