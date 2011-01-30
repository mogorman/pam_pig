#include <sys/param.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <curl/curl.h>

#ifdef MACOSX
#include <pam/pam_appl.h>
#else
#include <security/pam_appl.h>
#endif

#ifndef PAM_EXTERN
#define PAM_EXTERN
#endif
#define DOMAIN_LENGTH 255

#ifdef HAVE_LIBLDAP
#include <ldap.h>
#define PORT_NUMBER  LDAP_PORT
#endif

#define DEBUG printf

static char password_prompt[] = "Oink:";


/*
 * This function will look in ldap id the token correspond to the
 * requested user. It will returns 0 for failure and 1 for success.
 *
 * For the moment ldaps is not supported. ldap serve can be on a
 * remote host.
 *
 * You need the following parameters in you pam config:
 * ldapserver=  OR ldap_uri=
 * ldapdn=
 * user_attr=
 * yubi_attr=
 *
 */
static char * authorize_user_token_ldap (const char *ldapserver,
			   const char *ldap_uri,
			   const char *ldapdn,
			   const char *user_attr,
			   const char *yubi_attr,
			   const char *user)
{

  DEBUG(("called"));
  int retval = 0;
#ifdef HAVE_LIBLDAP
  LDAP *ld;
  LDAPMessage *result, *e;
  BerElement *ber;
  char *a;

  struct berval **vals;
  int i, rc;

  /* Allocation of memory for search strings depending on input size */
  char *find = malloc((strlen(user_attr)+strlen(ldapdn)+strlen(user)+3)*sizeof(char));
  char *sr = malloc((strlen(yubi_attr)+4)*sizeof(char));

  char sep[2] = ",";
  char eq[2] = "=";
  char sren[4] = "=*)";

  sr[0] = '(';
  sr[1] = '\0';
  find[0]='\0';

  strcat (find, user_attr);
  strcat (find, eq);
  strcat (find, user);
  strcat (find, sep);
  strcat (find, ldapdn);

  strcat (sr, yubi_attr);
  strcat (sr, sren);

  DEBUG(("find: %s",find));
  DEBUG(("sr: %s",sr));

  /* Get a handle to an LDAP connection. */
  if (ldap_uri)
    {
      rc = ldap_initialize (&ld,ldap_uri);
      if (rc != LDAP_SUCCESS)
	{
	  DEBUG (("ldap_init: %s", ldap_err2string (rc)));
	  return NULL;
	}
    }
  else
    {
      if ((ld = ldap_init (ldapserver, PORT_NUMBER)) == NULL)
	{
	  DEBUG (("ldap_init"));
	  return NULL;
	}
    }

  /* Bind anonymously to the LDAP server. */
  rc = ldap_simple_bind_s (ld, NULL, NULL);
  if (rc != LDAP_SUCCESS)
    {
      DEBUG (("ldap_simple_bind_s: %s", ldap_err2string (rc)));
      return NULL;
    }

  /* Search for the entry. */
  DEBUG (("ldap-dn: %s", find));
  DEBUG (("ldap-filter: %s", sr));

  if ((rc = ldap_search_ext_s (ld, find, LDAP_SCOPE_BASE,
			       sr, NULL, 0, NULL, NULL, LDAP_NO_LIMIT,
			       LDAP_NO_LIMIT, &result)) != LDAP_SUCCESS)
    {
      DEBUG (("ldap_search_ext_s: %s", ldap_err2string (rc)));

      return NULL;
    }

  e = ldap_first_entry (ld, result);
  if (e != NULL)
    {

      /* Iterate through each attribute in the entry. */
      for (a = ldap_first_attribute (ld, e, &ber);
	   a != NULL; a = ldap_next_attribute (ld, e, ber))
	{
	  if ((vals = ldap_get_values_len (ld, e, a)) != NULL)
	    {
	      for (i = 0; vals[i] != NULL; i++)
		{
                        return vals[i]->bv_val;
		}
	      ldap_value_free (vals);
	    }
	  ldap_memfree (a);
	}
      if (ber != NULL)
	{
	  ber_free (ber, 0);
	}

    }

  ldap_msgfree (result);
  ldap_unbind (ld);

  /* free memory allocated for search strings */
  free(find);
  free(sr);

#else
  DEBUG (("Trying to use LDAP, but this function is not compiled in pam_yubico!!"));
  DEBUG (("Install libldap-dev and then recompile pam_yubico."));
#endif
  return NULL;
}


/* This is a BS function to stop libcurl from printing out any text. */
size_t write_data(void *buffer, size_t size, size_t nmemb, void *userp)
{
        return size;
}

int check_key(const char *id, const char *url, const char *hash)
{
        char domain [DOMAIN_LENGTH] = {0};
        CURL *curl;
        CURLcode res;

        curl = curl_easy_init();
        if(strlen(hash) != 6) {
                return PAM_AUTH_ERR; //It should be impossible to get here
        }
        if(curl) {
                strncat(domain, url, DOMAIN_LENGTH);
                strncat(domain, id, DOMAIN_LENGTH);
                strncat(domain, "/", DOMAIN_LENGTH);
                strncat(domain, hash, DOMAIN_LENGTH);
                curl_easy_setopt(curl, CURLOPT_URL, domain);
                curl_easy_setopt(curl, CURLOPT_VERBOSE, 0);
		curl_easy_setopt(curl, CURLOPT_TIMEOUT, 100);
		curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT,200);
                curl_easy_setopt(curl, CURLOPT_DEBUGFUNCTION, 0);
                curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data);
                res = curl_easy_perform(curl);

                long http_code = 0;
                curl_easy_getinfo (curl, CURLINFO_RESPONSE_CODE, &http_code);
                if (http_code == 200 && res != CURLE_ABORTED_BY_CALLBACK)
                {
                        /* always cleanup */
                        curl_easy_cleanup(curl);
                        return PAM_SUCCESS;
                        //Succeeded
                } else {
                        /* always cleanup */
			if(res == CURLE_COULDNT_RESOLVE_HOST || res == CURLE_OPERATION_TIMEDOUT
                           || res == CURLE_COULDNT_CONNECT) {
                                curl_easy_cleanup(curl);
				return PAM_AUTHINFO_UNAVAIL;
                        //Failed
                        }
                        curl_easy_cleanup(curl);
                        return PAM_AUTH_ERR;
                }
        }
        return PAM_AUTH_ERR;
}

/* pam arguments are normally of the form name=value.  This gets the
 * 'value' corresponding to the passed 'name' from the argument
 * list. */
static const char *getarg(const char *name, int argc, const char **argv) {
  int len = strlen(name);
  while (argc) {
    if (strlen(*argv) > len &&
        !strncmp(name, *argv, len) &&
        (*argv)[len] == '=') {
      return *argv + len + 1;  /* 1 for the = */
    }
    argc--;
    argv++;
  }
  return 0;
}

PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags,
	int argc, const char *argv[])
{
	const void *ptr;
	const struct pam_conv *conv;
	struct pam_message msg;
	const struct pam_message *msgp;
	struct pam_response *resp;
	const char *user;
	char *crypt_password, *password, *key;
	int pam_err, retry;
	int system_is_down = 0;
        int stacked_pass = 0;
        char id [20] = {0};
        char id_path [DOMAIN_LENGTH] = {0};
        FILE *id_file;
        const char *url = getarg("url", argc, argv);
        const char *id_folder = getarg("id_folder", argc, argv);
	const char *system = getarg("system_is_down", argc, argv);
        const char *stacked = getarg("stacked_pass", argc, argv);
        const char *ldap_server = getarg("ldap_server", argc, argv);
	const char *ldap_uri = getarg("ldap_uri", argc, argv);
        const char *ldap_dn = getarg("ldap_dn", argc, argv);
        const char *ldap_user_attr = getarg("ldap_user_attr", argc, argv);
	const char *ldap_pig_attr = getarg("ldap_pig_attr", argc, argv);
        char hash [7] = {0};
        char cleaned_password[DOMAIN_LENGTH] = {0};
	if( system && (!strcmp("allow",system))) {
		system_is_down = 1;
	}
	if( system && (!strcmp("yes",stacked))) {
		stacked_pass = 1;
	}
        if(!url)
                url = "http://localhost:4240/auth/";
        if(!id_folder)
                id_folder = "/etc/pig/ids/";
	/* identify user */
	if ((pam_err = pam_get_user(pamh, &user, NULL)) != PAM_SUCCESS)
		return (pam_err);
	/* get password */
	pam_err = pam_get_item(pamh, PAM_CONV, &ptr);
	if (pam_err != PAM_SUCCESS)
		return (PAM_SYSTEM_ERR);
	conv = ptr;
	msgp = &msg;
	msg.msg_style = PAM_PROMPT_ECHO_OFF;
	msg.msg = password_prompt;

	password = NULL;
	for (retry = 0; retry < 3; ++retry) {
		resp = NULL;
		pam_err = (*conv->conv)(1, &msgp, &resp, conv->appdata_ptr);
		if (resp != NULL) {
			if (pam_err == PAM_SUCCESS) {
				password = resp->resp;
                                if(strlen(password) < 6) {
                                        return (PAM_AUTH_ERR);
                                } else {
                                       key = password + (strlen(password) - 6);
                                       strcpy(hash, key);
                                       if(stacked_pass && strlen(password) < 260) {
                                               strncpy(cleaned_password, password, (strlen(password) - 6));
                                               pam_set_item(pamh, PAM_AUTHTOK, cleaned_password);
                                               pam_set_item(pamh, PAM_OLDAUTHTOK, cleaned_password);
                                       }
                                }
                        } else {
				free(resp->resp);
                        }
			free(resp);
		}
		if (pam_err == PAM_SUCCESS)
			break;
	}
	if (pam_err == PAM_CONV_ERR)
		return (pam_err);
	if (pam_err != PAM_SUCCESS)
		return (PAM_AUTH_ERR);
        if(!ldap_server) {
                strncat(id_path, id_folder, DOMAIN_LENGTH);
                strncat(id_path, user, DOMAIN_LENGTH);
                if(!(id_file = fopen(id_path, "r"))) {
                        return PAM_AUTH_ERR;
                }
                if(fread(id, 20,1, id_file) != 1) {
                        fclose(id_file);
                        return PAM_AUTH_ERR;
                }
                fclose(id_file);
        } else {
#ifdef HAVE_LIBLDAP
                strncat(id,
                        ldap_get_user_id(ldap_server, ldap_uri, ldap_dn, ldap_user_attr,
                                         ldap_pig_attr, user), 20);
                if(id[0] = '\0') {
                        return PAM_AUTH_ERR;
                }
#else
                return PAM_AUTH_ERR;
#endif
        }
        pam_err = check_key(id, url, hash);
        if (pam_err == PAM_AUTHINFO_UNAVAIL && system_is_down) {
                pam_err = PAM_SUCCESS;
        }

	return (pam_err);
}

PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh, int flags,
	int argc, const char *argv[])
{

	return (PAM_SUCCESS);
}

PAM_EXTERN int
pam_sm_acct_mgmt(pam_handle_t *pamh, int flags,
	int argc, const char *argv[])
{

	return (PAM_SUCCESS);
}

PAM_EXTERN int
pam_sm_open_session(pam_handle_t *pamh, int flags,
	int argc, const char *argv[])
{

	return (PAM_SUCCESS);
}

PAM_EXTERN int
pam_sm_close_session(pam_handle_t *pamh, int flags,
	int argc, const char *argv[])
{

	return (PAM_SUCCESS);
}

PAM_EXTERN int
pam_sm_chauthtok(pam_handle_t *pamh, int flags,
	int argc, const char *argv[])
{

	return (PAM_SERVICE_ERR);
}

#ifdef PAM_MODULE_ENTRY
PAM_MODULE_ENTRY("pam_pig");
#endif
