#ifndef __IPSTAT_H
#define __IPSTAT_H

#include <arpa/inet.h>
#include <curl/curl.h>
#include <json-c/json.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* the shortest valid IPv4 address is x.x.x.x and the longest is xxx.xxx.xxx.xxx
   we use these lengths to validate in ipv4_addr_parse() */
#define IPV4_ADDR_LEN_SHORTEST 7
#define IPV4_ADDR_LEN_LONGEST 15

/* define the maximum number of octets in IPv4 and their maximum lengths */
#define IPV4_OCTET_COUNT 4
#define IPV4_OCTET_LENGTH 3

// user agent string to use for HTTP requests
#define IPSTAT_USER_AGENT "ipstat/0.1.0"

struct ipv4_addr {
    union {
        uint8_t octets[IPV4_OCTET_COUNT];
        uint32_t address;
    };
};

struct ipstat {
    char *ip;
    char *hostname;
    bool anycast;
    char *city;
    char *region;
    char *country;
    char *location;
    char *org;
    char *postcode;
    char *timezone;
    char *readme;
};

typedef enum {
    ERROR_NONE,

    DNS_ERROR_COULDNT_RESOLVE_HOSTNAME,

    FORMAT_ERROR_INVALID_SUBSTITUTION,
    FORMAT_ERROR_MISSING_SUBSTITUTION,

    HTTP_ERROR_GET_REQUEST_FAILED,

    PARSE_ERROR_INVALID_LENGTH,
    PARSE_ERROR_INVALID_CHARACTER,
    PARSE_ERROR_INVALID_JSON,
    PARSE_ERROR_INVALID_OCTET,
    PARSE_ERROR_JSON_INVALID_TYPE_IP,
    PARSE_ERROR_JSON_MISSING_IP,
    PARSE_ERROR_MISSING_OCTET,
    PARSE_ERROR_TOO_MANY_OCTETS
} ipstat_error;

static const char *const ipstat_error_messages[] = {
    [ERROR_NONE] = "No error occurred",

    [DNS_ERROR_COULDNT_RESOLVE_HOSTNAME] = "Unable to resolve provided hostname",

    [FORMAT_ERROR_INVALID_SUBSTITUTION] =
        "The provided endpoint URI format string has an invalid substitution",
    [FORMAT_ERROR_MISSING_SUBSTITUTION] =
        "The provided endpoint URI format string has no substitution",

    [HTTP_ERROR_GET_REQUEST_FAILED] = "HTTP GET request failed: ",

    [PARSE_ERROR_INVALID_LENGTH] = "The provided IP address string is of an invalid length",
    [PARSE_ERROR_INVALID_CHARACTER] =
        "The provided IP address string contains an invalid character",
    [PARSE_ERROR_INVALID_OCTET] = "An octet within the provided IP address string is invalid",
    [PARSE_ERROR_JSON_INVALID_TYPE_IP] = "JSON response provides invalid value type for key \"ip\"",
    [PARSE_ERROR_JSON_MISSING_IP] = "JSON response is missing expected key \"ip\"",
    [PARSE_ERROR_MISSING_OCTET] = "The provided IP address string is missing an octet",
    [PARSE_ERROR_TOO_MANY_OCTETS] = "The provided IP address string contains too many octets",
    [PARSE_ERROR_INVALID_JSON] = "Unable to parse JSON data in HTTP response",
};

struct response_buffer {
    char *data;
    size_t length;
};

typedef enum {
    RETURN_CODE_SUCCESS = 0,
    RETURN_CODE_PARSE_ERROR = 1,
    RETURN_CODE_FORMAT_ERROR = 2,
    RETURN_CODE_HTTP_ERROR = 3,
    RETURN_CODE_IPSTAT_PARSE_ERROR = 4,
    RETURN_CODE_UNKNOWN_OPTION = 5,
    RETURN_CODE_MISSING_OPTION = 6,
    RETURN_CODE_DNS_ERROR = 7
} return_code;

static const return_code const ipstat_error_return_codes[] = {
    [ERROR_NONE] = RETURN_CODE_SUCCESS,

    [DNS_ERROR_COULDNT_RESOLVE_HOSTNAME] = RETURN_CODE_DNS_ERROR,

    [FORMAT_ERROR_INVALID_SUBSTITUTION] = RETURN_CODE_FORMAT_ERROR,
    [FORMAT_ERROR_MISSING_SUBSTITUTION] = RETURN_CODE_FORMAT_ERROR,

    [HTTP_ERROR_GET_REQUEST_FAILED] = RETURN_CODE_HTTP_ERROR,

    [PARSE_ERROR_INVALID_LENGTH] = RETURN_CODE_PARSE_ERROR,
    [PARSE_ERROR_INVALID_CHARACTER] = RETURN_CODE_PARSE_ERROR,
    [PARSE_ERROR_INVALID_OCTET] = RETURN_CODE_PARSE_ERROR,
    [PARSE_ERROR_JSON_INVALID_TYPE_IP] = RETURN_CODE_IPSTAT_PARSE_ERROR,
    [PARSE_ERROR_JSON_MISSING_IP] = RETURN_CODE_IPSTAT_PARSE_ERROR,
    [PARSE_ERROR_MISSING_OCTET] = RETURN_CODE_PARSE_ERROR,
    [PARSE_ERROR_TOO_MANY_OCTETS] = RETURN_CODE_PARSE_ERROR,
    [PARSE_ERROR_INVALID_JSON] = RETURN_CODE_IPSTAT_PARSE_ERROR,
};

_Noreturn void fatal_error(const char *, return_code);
struct ipstat *fetch_ipstat(const char *, const char *, ipstat_error *);
char *format_endpoint_uri(const char *, struct ipv4_addr *, ipstat_error *);
void ipstat_free(struct ipstat *);
struct ipstat *ipstat_init();
void ipstat_print(FILE *, struct ipstat *);
struct ipv4_addr *ipv4_addr_parse(const char *, ipstat_error *);
char *ipv4_addr_to_string(const struct ipv4_addr *);
char *ipv4_addr_get_hostname(const struct ipv4_addr *);
struct response_buffer *issue_get_request(const char *);
struct ipstat *parse_ipstat(struct response_buffer *, ipstat_error *);
void response_buffer_free(struct response_buffer *);
struct response_buffer *response_buffer_init();
static size_t response_buffer_write(void *, size_t, size_t, void *);

/*
    _Noreturn void fatal_error(const char *message, return_code code)

    Outputs the provided message string to stderr and exits with the provided return code
*/
_Noreturn void fatal_error(const char *message, return_code code) {
    fprintf(stderr, "Fatal error: %s\n", message);
    exit(code);
}

/*
    struct ipstat *fetch_ipstat(
        struct ipv4_addr *target_addr,
        const char *endpoint_uri_format,
        ipstat_error *fetch_error
    )

    Fetches an ipstat instance containing data for the provided target address
    using the provided JSON endpoint URI format string. Any errors will be
    returned in fetch_error.

    Note that any allocated ipstat instance will be automatically freed in the event
    an error occurs and the return pointer will be NULL
*/
struct ipstat *fetch_ipstat(
    const char *target_ip_addr, const char *endpoint_uri_format, ipstat_error *fetch_error
) {
    // parse the incoming ip address to validate it and check for an error
    ipstat_error error = ERROR_NONE;
    struct ipv4_addr *target_addr = ipv4_addr_parse(target_ip_addr, &error);
    if (error != ERROR_NONE) {
        *fetch_error = error;
        return NULL;
    }

    // insert the ip address into the endpoint format string
    char *endpoint_uri = format_endpoint_uri(endpoint_uri_format, target_addr, &error);
    if (error != ERROR_NONE) {
        *fetch_error = error;
        return NULL;
    }

    // issue a GET request for the target URI and try parsing the response
    struct response_buffer *response = issue_get_request(endpoint_uri);
    struct ipstat *stats = parse_ipstat(response, &error);
    if (error != ERROR_NONE) {
        *fetch_error = error;
        response_buffer_free(response);
        ipstat_free(stats);
        return NULL;
    }

    // try to get the hostname for this ip
    stats->hostname = ipv4_addr_get_hostname(target_addr);

    // clean up after ourselves
    response_buffer_free(response);
    free(endpoint_uri);
    free(target_addr);

    return stats;
}

/*
    char *format_endpoint_uri(
        const char *endpoint_uri_format,
        struct ipv4_addr *target_addr,
        ipstat_error *format_error
    )

    Replaces the first occurrence of "{}" in the provided format string with
    the string representation of the provided ipv4_addr (i.e., 192.168.1.1).
    Any errors will be returned in format_error.

    Note that any allocated buffer will be freed in the case that a format error
    occurs and the return pointer will be NULL
*/
char *format_endpoint_uri(
    const char *endpoint_uri_format, struct ipv4_addr *target_addr, ipstat_error *format_error
) {
    // loop over the endpoint uri and find the index to format
    unsigned int format_str_length = strlen(endpoint_uri_format);
    unsigned int format_offset;
    for (format_offset = 0; format_offset < format_str_length; format_offset++) {
        // keep looping until we find an '{'
        if (*(endpoint_uri_format + format_offset) == '{') {
            break;
        }
    }

    /* check if we found a '{' before the end of the format string and that the next character
       is a closing brace '}' */
    if (format_offset >= format_str_length) {
        *format_error = FORMAT_ERROR_MISSING_SUBSTITUTION;
        return NULL;
    }
    if (format_offset + 1 >= format_str_length ||
        *(endpoint_uri_format + format_offset + 1) != '}') {
        *format_error = FORMAT_ERROR_INVALID_SUBSTITUTION;
        return NULL;
    }

    // allocate a buffer of sufficient length to contain the endpoint URL and IPv4 address
    char *endpoint_uri = malloc(sizeof(char) * (format_str_length - 2 + IPV4_ADDR_LEN_LONGEST + 1));

    // copy the format string up to the '{' into the endpoint uri then terminate the formatted url
    // and increment beyond the '{}'
    int format_index;
    for (format_index = 0; format_index < format_offset; format_index++) {
        *(endpoint_uri + format_index) = *(endpoint_uri_format + format_index);
    }
    *(endpoint_uri + format_index) = '\0';
    format_index += 2;

    // convert/append the ipv4 address as a string
    char *ipv4_addr_string = ipv4_addr_to_string(target_addr);
    strcat(endpoint_uri, ipv4_addr_string);
    free(ipv4_addr_string);

    // append the rest of the format string
    strcat(endpoint_uri, endpoint_uri_format + format_index);

    return endpoint_uri;
}

/*
    char *hostname_get_ipv4_addr(const char *hostname, ipstat_error *error)

    Attempts to get an IPv4 address as a string for the provided hostname.
    Any error will be returned in the provided ipstat_error pointer

    Note that if an error occurs, any allocated buffer will be freed and
    the return pointer will be NULL
*/
char *hostname_get_ipv4_addr(const char *hostname, ipstat_error *error) {
    // try resolving the hostname to an IP address
    struct hostent *ent = gethostbyname(hostname);
    if (ent == NULL) {
        *error = DNS_ERROR_COULDNT_RESOLVE_HOSTNAME;
        return NULL;
    }

    // get the first address for the host and strcpy it into a buffer
    char *best_addr_orig = inet_ntoa(*(((struct in_addr **)ent->h_addr_list)[0]));
    char *best_addr = malloc(sizeof(char) * strlen(best_addr_orig));
    *best_addr = '\0';
    strcpy(best_addr, best_addr_orig);

    *error = ERROR_NONE;
    return best_addr;
}

void ipstat_free(struct ipstat *to_free) {
    if (to_free == NULL) {
        return;
    }

    free(to_free->ip);
    free(to_free->hostname);
    free(to_free->city);
    free(to_free->region);
    free(to_free->country);
    free(to_free->location);
    free(to_free->org);
    free(to_free->postcode);
    free(to_free->timezone);
    free(to_free->readme);

    free(to_free);
}

struct ipstat *ipstat_init() {
    struct ipstat *new_ipstat = malloc(sizeof(struct ipstat));

    new_ipstat->ip = NULL;
    new_ipstat->anycast = false;
    new_ipstat->city = NULL;
    new_ipstat->region = NULL;
    new_ipstat->country = NULL;
    new_ipstat->location = NULL;
    new_ipstat->org = NULL;
    new_ipstat->postcode = NULL;
    new_ipstat->timezone = NULL;
    new_ipstat->readme = NULL;

    return new_ipstat;
}

void ipstat_print(FILE *target_file, struct ipstat *to_print) {
    fprintf(target_file, "Address:       %s\n", to_print->ip);
    if (to_print->hostname != NULL) {
        fprintf(target_file, "Host:          %s\n", to_print->hostname);
    }
    if (to_print->anycast) {
        fprintf(target_file, "Anycast:       Yes\n");
    } else {
        fprintf(target_file, "Anycast:       No\n");
    }
    if (to_print->city != NULL) {
        fprintf(target_file, "City:          %s\n", to_print->city);
    }
    if (to_print->region != NULL) {
        fprintf(target_file, "Region:        %s\n", to_print->region);
    }
    if (to_print->country != NULL) {
        fprintf(target_file, "Country:       %s\n", to_print->country);
    }
    if (to_print->location != NULL) {
        fprintf(target_file, "Location:      %s\n", to_print->location);
    }
    if (to_print->org != NULL) {
        fprintf(target_file, "Organization:  %s\n", to_print->org);
    }
    if (to_print->postcode != NULL) {
        fprintf(target_file, "Postal code:   %s\n", to_print->postcode);
    }
    if (to_print->timezone != NULL) {
        fprintf(target_file, "Timezone:      %s\n", to_print->timezone);
    }
}

/*
    struct ipv4_addr *ipv4_addr_parse(const char *address, int &parse_error)

    Parses an incoming IPv4 address string into an instance of struct
    ipv4_addr. Returns NULL and populates &parse_error in the case of
    a parse error.
*/
struct ipv4_addr *ipv4_addr_parse(const char *address, ipstat_error *parse_error) {
    // check if this looks like a v4 address based on length
    size_t address_len = strlen(address);
    if (address_len < IPV4_ADDR_LEN_SHORTEST || address_len > IPV4_ADDR_LEN_LONGEST) {
        *parse_error = PARSE_ERROR_INVALID_LENGTH;
        return NULL;
    }

    // allocate a new ipv4_addr instance
    struct ipv4_addr *parsed_addr = malloc(sizeof(struct ipv4_addr));

    // loop over and try parsing the ipv4 address into octets
    int index = 0, octet_buf_offset = 0, current_octet = 0;
    char octet_buf[IPV4_OCTET_LENGTH + 1];
    while (index < address_len) {
        // get the current octet as a string
        octet_buf_offset = 0;
        while (octet_buf_offset < IPV4_OCTET_LENGTH) {
            // check if this is a valid digit or '.'
            switch (*(address + index)) {
                // digit. store it in the buffer and continue
                case '0':
                case '1':
                case '2':
                case '3':
                case '4':
                case '5':
                case '6':
                case '7':
                case '8':
                case '9':
                    *(octet_buf + octet_buf_offset) = *(address + index);
                    break;

                // end of octet, break switch and the outer while loop
                case '\0':
                case '.':
                    goto end_of_octet;

                // invalid character. free the struct instance and return an error
                default:
                    free(parsed_addr);
                    *parse_error = PARSE_ERROR_INVALID_CHARACTER;
                    return NULL;
            }

            // go to the next character and next index
            octet_buf_offset++;
            index++;
        }
    end_of_octet:
        // check if we're pointing at a '.' separator or the null terminator. also, we need
        // to have something in the octet buffer (i.e., not an empty string). if neither
        // is true, the octet was invalid
        if (*(address + index) != '.' && *(address + index) != '\0' || octet_buf_offset == 0) {
            free(parsed_addr);
            *parse_error = PARSE_ERROR_INVALID_OCTET;
            return NULL;
        }

        // null terminate then parse the octet. validate that it's in the range 0-255
        *(octet_buf + octet_buf_offset) = '\0';
        int parsed_value = atoi((char *)&octet_buf);
        if (parsed_value > UINT8_MAX) {
            free(parsed_addr);
            *parse_error = PARSE_ERROR_INVALID_OCTET;
            return NULL;
        }
        parsed_addr->octets[current_octet] = parsed_value;
        current_octet++;

        // check that we didn't receive too many octets (more than 4)
        if (current_octet > IPV4_OCTET_COUNT) {
            free(parsed_addr);
            *parse_error = PARSE_ERROR_TOO_MANY_OCTETS;
            return NULL;
        }

        // go to the next character beyond the '.'
        index++;
    }

    // final check that we didn't receive too many or too few octets (more/less than 4)
    if (current_octet > IPV4_OCTET_COUNT) {
        free(parsed_addr);
        *parse_error = PARSE_ERROR_TOO_MANY_OCTETS;
        return NULL;
    } else if (current_octet < IPV4_OCTET_COUNT) {
        free(parsed_addr);
        *parse_error = PARSE_ERROR_MISSING_OCTET;
        return NULL;
    }

    // set no error and return the instance
    *parse_error = ERROR_NONE;
    return parsed_addr;
}

/*
    char *ipv4_addr_to_string(const struct ipv4_addr *to_convert)

    Converts the provided ipv4_addr instance to a string representation
    (i.e., 192.168.1.1)
*/
char *ipv4_addr_to_string(const struct ipv4_addr *to_convert) {
    // allocate a char buffer of the maximum length + 1
    unsigned int addr_buffer_size = sizeof(char) * (IPV4_ADDR_LEN_LONGEST + 1);
    char *addr_buffer = malloc(addr_buffer_size);
    *addr_buffer = '\0';

    // convert all of the octets into strings and concatenate them
    unsigned int octet_buffer_length = sizeof(char) * (IPV4_OCTET_LENGTH + 1);
    for (int octet_index = 0; octet_index < IPV4_OCTET_COUNT; octet_index++) {
        // convert the current octet into a string
        char *current_octet = malloc(octet_buffer_length);
        snprintf(current_octet, octet_buffer_length, "%d", to_convert->octets[octet_index]);

        /* concatenate the current octet to the overall string. include a '.' for all but
           the final octet */
        strcat(addr_buffer, current_octet);
        if (octet_index < IPV4_OCTET_COUNT - 1) {
            strcat(addr_buffer, ".");
        }

        // free the current octet string
        free(current_octet);
    }

    // return the address as a string
    return addr_buffer;
}

/*
    char *ipv4_addr_get_hostname(const struct ipv4_addr *target)

    Attempts to get a hostname associated with the provided ipv4_addr. Returns
    NULL if a hostname couldn't be resolved
*/
char *ipv4_addr_get_hostname(const struct ipv4_addr *target) {
    // convert the ipv4 address to a string
    char *addr_string = ipv4_addr_to_string(target);

    /* try getting a hostname for the address. either copy the name into a buffer
       and return it or return NULL if no hostname found. also, free the address string
       after it's been used */
    struct in_addr address;
    inet_aton(addr_string, &address);
    free(addr_string);
    struct hostent *ent = gethostbyaddr((const void *)&address, sizeof(struct in_addr), AF_INET);

    if (ent == NULL) {
        return NULL;
    }

    char *hostname = malloc(sizeof(char) * strlen(ent->h_name));
    strcpy(hostname, ent->h_name);

    return hostname;
}

/*
    struct response_buffer *issue_get_request(const char *uri)

    Issues an HTTP GET request to the provided uri and returns the resultant data in\
    a response_buffer instance. Calls fatal_error() if an issue occurs
*/
struct response_buffer *issue_get_request(const char *uri) {
    curl_global_init(CURL_GLOBAL_ALL);

    // initialize a curl instance and a response buffer to hold results
    CURL *curl_handle = curl_easy_init();
    CURLcode curl_err_code;
    struct response_buffer *response = response_buffer_init();

    // set up the attributes of our curl instance
    curl_easy_setopt(curl_handle, CURLOPT_URL, uri);
    curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, response_buffer_write);
    curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *)response);
    curl_easy_setopt(curl_handle, CURLOPT_USERAGENT, IPSTAT_USER_AGENT);

    // issue the GET request and throw an error as necessary
    curl_err_code = curl_easy_perform(curl_handle);
    if (curl_err_code != CURLE_OK) {
        const char *curl_error_msg = curl_easy_strerror(curl_err_code);
        const char *ipstat_error_prefix = ipstat_error_messages[HTTP_ERROR_GET_REQUEST_FAILED];
        char *full_error_message =
            malloc(sizeof(char) * (strlen(curl_error_msg) + strlen(ipstat_error_prefix) + 1));
        *full_error_message = '\0';

        strcat(full_error_message, ipstat_error_prefix);
        strcat(full_error_message, curl_error_msg);

        fatal_error(full_error_message, RETURN_CODE_HTTP_ERROR);
    }

    curl_easy_cleanup(curl_handle);
    curl_global_cleanup();
    return response;
}

/*
    struct ipstat *parse_ipstat(struct response_buffer *buffer, ipstat_error *parse_error)

    Parses the JSON response contained in the provided response_buffer into an
    ipstat instance. Any errors will be returned in parse_error.

    Note that anything allocated will be freed if an error occurs.
*/
struct ipstat *parse_ipstat(struct response_buffer *buffer, ipstat_error *parse_error) {
    // try parsing the buffer as JSON and return an error if we get an error
    struct json_tokener *json_tok = json_tokener_new();
    struct json_object *json_obj = json_tokener_parse_ex(json_tok, buffer->data, buffer->length);
    if (json_tokener_get_error(json_tok) != json_tokener_success) {
        *parse_error = PARSE_ERROR_INVALID_JSON;
        json_tokener_free(json_tok);
        json_object_put(json_obj);
        return NULL;
    }

    // read the results into a new ipstat instance
    struct ipstat *stats = ipstat_init();

    // -- ip --
    struct json_object *target = json_object_object_get(json_obj, "ip");
    if (target == NULL) {
        *parse_error = PARSE_ERROR_JSON_MISSING_IP;
        json_tokener_free(json_tok);
        json_object_put(json_obj);
        return NULL;
    }
    const char *value = json_object_get_string(target);
    if (value == NULL) {
        *parse_error = PARSE_ERROR_JSON_INVALID_TYPE_IP;
        json_tokener_free(json_tok);
        json_object_put(json_obj);
        return NULL;
    }
    stats->ip = malloc(sizeof(char) * (strlen(value) + 1));
    strcpy(stats->ip, value);

    // -- city --
    target = json_object_object_get(json_obj, "city");
    if (target != NULL) {
        const char *value = json_object_get_string(target);
        if (value != NULL) {
            stats->city = malloc(sizeof(char) * (strlen(value) + 1));
            strcpy(stats->city, value);
        }
    }

    // -- region --
    target = json_object_object_get(json_obj, "region");
    if (target != NULL) {
        const char *value = json_object_get_string(target);
        if (value != NULL) {
            stats->region = malloc(sizeof(char) * (strlen(value) + 1));
            strcpy(stats->region, value);
        }
    }

    // -- country --
    target = json_object_object_get(json_obj, "country");
    if (target != NULL) {
        const char *value = json_object_get_string(target);
        if (value != NULL) {
            stats->country = malloc(sizeof(char) * (strlen(value) + 1));
            strcpy(stats->country, value);
        }
    }

    // -- location --
    target = json_object_object_get(json_obj, "loc");
    if (target != NULL) {
        const char *value = json_object_get_string(target);
        if (value != NULL) {
            stats->location = malloc(sizeof(char) * (strlen(value) + 1));
            strcpy(stats->location, value);
        }
    }

    // -- org --
    target = json_object_object_get(json_obj, "org");
    if (target != NULL) {
        const char *value = json_object_get_string(target);
        if (value != NULL) {
            stats->org = malloc(sizeof(char) * (strlen(value) + 1));
            strcpy(stats->org, value);
        }
    }

    // -- postcode --
    target = json_object_object_get(json_obj, "postal");
    if (target != NULL) {
        const char *value = json_object_get_string(target);
        if (value != NULL) {
            stats->postcode = malloc(sizeof(char) * (strlen(value) + 1));
            strcpy(stats->postcode, value);
        }
    }

    // -- timezone --
    target = json_object_object_get(json_obj, "timezone");
    if (target != NULL) {
        const char *value = json_object_get_string(target);
        if (value != NULL) {
            stats->timezone = malloc(sizeof(char) * (strlen(value) + 1));
            strcpy(stats->timezone, value);
        }
    }

    // -- anycast --
    target = json_object_object_get(json_obj, "anycast");
    if (target != NULL) {
        stats->anycast = json_object_get_boolean(target);
    }

    // free the json object
    json_tokener_free(json_tok);
    json_object_put(json_obj);
    return stats;
}

/*
    void response_buffer_free(struct response_buffer *to_free)

    Deallocates the provided response_buffer instance.
*/
void response_buffer_free(struct response_buffer *to_free) {
    if (to_free == NULL) {
        return;
    }

    free(to_free->data);
    free(to_free);
}

/*
    struct response_buffer *response_buffer_init()

    Allocates and returns a new response_buffer containing no data
*/
struct response_buffer *response_buffer_init() {
    struct response_buffer *buffer = malloc(sizeof(struct response_buffer));

    buffer->data = NULL;
    buffer->length = 0;

    return buffer;
}

/*
    static size_t response_buffer_write(
        void *data, size_t char_size, size_t buf_len, void *target_buffer
    )

    Callback for libcurl when data is received. Writes the data to the
    response_buffer instance pointer provided in target_buffer
*/
static size_t response_buffer_write(
    void *data, size_t char_size, size_t buf_len, void *target_buffer
) {
    // get the underlying size of the data buffer in bytes
    unsigned int data_size = char_size * buf_len;

    // if the response buffer is of zero size, perform an initial alloc
    struct response_buffer *buffer = (struct response_buffer *)target_buffer;
    if (buffer->length == 0) {
        buffer->data = malloc(data_size + 1);
    } else {
        buffer->data = realloc(buffer->data, buffer->length + data_size + 1);
    }

    // copy the incoming data onto the end of the buffer and store the new size
    memcpy(&(buffer->data[buffer->length]), data, data_size);
    buffer->length += data_size;
    buffer->data[buffer->length] = '\0';

    return data_size;
}

#endif  // __IPSTAT_H