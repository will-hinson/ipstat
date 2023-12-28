#include "ipstat.h"

#include <getopt.h>
#include <stdio.h>

/* the default endpoint uri format. may be overriden with '-e' */
static char *default_endpoint_uri_format = "https://ipinfo.io/{}/json";

_Noreturn void show_usage(char *image_name, return_code code) {
    fprintf(stderr, "usage: %s [-e endpoint_format] [-h hostname] ip_address\n", image_name);
    exit(code);
}

int main(int argc, char *const argv[]) {
    ipstat_error error = ERROR_NONE;

    /* parse incoming arguments. there is an optional endpoint uri and required
       positional target ip address */
    char *endpoint_uri_format = malloc(sizeof(char) * (strlen(default_endpoint_uri_format) + 1));
    strcpy(endpoint_uri_format, default_endpoint_uri_format);
    char *target_ip_addr = NULL;

    int opt;
    while ((opt = getopt(argc, argv, "e:h:")) != -1) {
        switch (opt) {
            case 'e':
                strcpy(endpoint_uri_format, optarg);
                break;
            case 'h':
                char *hostname = hostname_get_ipv4_addr(optarg, &error);
                if (error != ERROR_NONE) {
                    fatal_error(ipstat_error_messages[error], RETURN_CODE_DNS_ERROR);
                }
                target_ip_addr = hostname;
                break;
            default:
                show_usage(argv[0], RETURN_CODE_UNKNOWN_OPTION);
        }
    }

    // check for/get the required positional argument if we didn't get a hostname
    if (target_ip_addr == NULL) {
        if (optind >= argc) {
            show_usage(argv[0], RETURN_CODE_MISSING_OPTION);
        }

        target_ip_addr = malloc(sizeof(char) * (strlen(*(argv + optind)) + 1));
        strcpy(target_ip_addr, *(argv + optind));
    }

    // get data for the provided endpoint uri and print it
    struct ipstat *stats = fetch_ipstat(target_ip_addr, endpoint_uri_format, &error);
    if (error != ERROR_NONE) {
        fatal_error(ipstat_error_messages[error], ipstat_error_return_codes[error]);
    }
    ipstat_print(stdout, stats);

    // free everything we allocated
    ipstat_free(stats);
    free(endpoint_uri_format);
    free(target_ip_addr);

    return RETURN_CODE_SUCCESS;
}