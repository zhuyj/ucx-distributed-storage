#include <ucp/api/ucp.h>

#include <string.h>    /* memset */
#include <arpa/inet.h> /* inet_addr */
#include <unistd.h>    /* getopt */
#include <stdlib.h>    /* atoi */

#define DEFAULT_PORT       13337
#define IP_STRING_LEN      50
#define PORT_STRING_LEN    8
#define TAG                0xCAFE
#define COMM_TYPE_DEFAULT  "STREAM"

static uint16_t server_port = DEFAULT_PORT;

typedef enum {
    CLIENT_SERVER_SEND_RECV_STREAM  = UCS_BIT(0),
    CLIENT_SERVER_SEND_RECV_TAG     = UCS_BIT(1),
    CLIENT_SERVER_SEND_RECV_DEFAULT = CLIENT_SERVER_SEND_RECV_STREAM
} send_recv_type_t;

/**
 * Server's application context to be used in the user's connection request
 * callback.
 * It holds the server's listener and the handle to an incoming connection request.
 */
typedef struct ucx_server_ctx {
    volatile ucp_conn_request_h conn_request;
    ucp_listener_h              listener;
} ucx_server_ctx_t;


/**
 * Stream request context. Holds a value to indicate whether or not the
 * request is completed.
 */
typedef struct test_req {
    int complete;
} test_req_t;

/**
 * The callback on the sending side, which is invoked after finishing sending
 * the message.
 */
static void send_cb(void *request, ucs_status_t status)
{
    test_req_t *req = request;

    req->complete = 1;

    printf("send_cb returned with status %d (%s)\n",
           status, ucs_status_string(status));
}

/**
 * Error handling callback.
 */
static void err_cb(void *arg, ucp_ep_h ep, ucs_status_t status)
{
    printf("error handling callback was invoked with status %d (%s)\n",
           status, ucs_status_string(status));
}

/**
 * Set an address for the server to listen on - INADDR_ANY on a well known port.
 */
void set_listen_addr(const char *address_str, struct sockaddr_in *listen_addr)
{
    /* The server will listen on INADDR_ANY */
    memset(listen_addr, 0, sizeof(struct sockaddr_in));
    listen_addr->sin_family      = AF_INET;
    listen_addr->sin_addr.s_addr = (address_str) ? inet_addr(address_str) : INADDR_ANY;
    listen_addr->sin_port        = htons(server_port);
}

/**
 * Set an address to connect to. A given IP address on a well known port.
 */
void set_connect_addr(const char *address_str, struct sockaddr_in *connect_addr)
{
    memset(connect_addr, 0, sizeof(struct sockaddr_in));
    connect_addr->sin_family      = AF_INET;
    connect_addr->sin_addr.s_addr = inet_addr(address_str);
    connect_addr->sin_port        = htons(server_port);
}

/**
 * Initialize the client side. Create an endpoint from the client side to be
 * connected to the remote server (to the given IP).
 */
static ucs_status_t start_client(ucp_worker_h ucp_worker, const char *ip,
                                 ucp_ep_h *client_ep)
{
    ucp_ep_params_t ep_params;
    struct sockaddr_in connect_addr;
    ucs_status_t status;

    set_connect_addr(ip, &connect_addr);

    /*
     * Endpoint field mask bits:
     * UCP_EP_PARAM_FIELD_FLAGS             - Use the value of the 'flags' field.
     * UCP_EP_PARAM_FIELD_SOCK_ADDR         - Use a remote sockaddr to connect
     *                                        to the remote peer.
     * UCP_EP_PARAM_FIELD_ERR_HANDLING_MODE - Error handling mode - this flag
     *                                        is temporarily required since the
     *                                        endpoint will be closed with
     *                                        UCP_EP_CLOSE_MODE_FORCE which
     *                                        requires this mode.
     *                                        Once UCP_EP_CLOSE_MODE_FORCE is
     *                                        removed, the error handling mode
     *                                        will be removed.
     */
    ep_params.field_mask       = UCP_EP_PARAM_FIELD_FLAGS       |
                                 UCP_EP_PARAM_FIELD_SOCK_ADDR   |
                                 UCP_EP_PARAM_FIELD_ERR_HANDLER |
                                 UCP_EP_PARAM_FIELD_ERR_HANDLING_MODE;
    ep_params.err_mode         = UCP_ERR_HANDLING_MODE_PEER;
    ep_params.err_handler.cb   = err_cb;
    ep_params.err_handler.arg  = NULL;
    ep_params.flags            = UCP_EP_PARAMS_FLAGS_CLIENT_SERVER;
    ep_params.sockaddr.addr    = (struct sockaddr*)&connect_addr;
    ep_params.sockaddr.addrlen = sizeof(connect_addr);

    status = ucp_ep_create(ucp_worker, &ep_params, client_ep);
    if (status != UCS_OK) {
        fprintf(stderr, "failed to connect to %s (%s)\n", ip, ucs_status_string(status));
    }

    return status;
}

/**
 * Progress the request until it completes.
 */
static ucs_status_t request_wait(ucp_worker_h ucp_worker, test_req_t *request)
{
    ucs_status_t status;

    /*  if operation was completed immediately */
    if (request == NULL) {
        return UCS_OK;
    }

    if (UCS_PTR_IS_ERR(request)) {
        return UCS_PTR_STATUS(request);
    }

    while (request->complete == 0) {
        ucp_worker_progress(ucp_worker);
    }
    status = ucp_request_check_status(request);

    /* This request may be reused so initialize it for next time */
    request->complete = 0;
    ucp_request_free(request);

    return status;
}

static void tag_recv_cb(void *request, ucs_status_t status,
                        ucp_tag_recv_info_t *info)
{
    test_req_t *req = request;

    req->complete = 1;

    printf("tag_recv_cb returned with status %d (%s), length: %lu, "
           "sender_tag: 0x%lX\n",
           status, ucs_status_string(status), info->length, info->sender_tag);
}

/**
 * Send and receive a message using the Tag-Matching API.
 * The client sends a message to the server and waits until the send it completed.
 * The server receives a message from the client and waits for its completion.
 */
static int send_recv_tag(ucp_worker_h ucp_worker, ucp_ep_h ep, int is_server)
{
    char *recv_message = NULL;
    test_req_t *request;
    size_t length = 64;
    ucs_status_t status;
    int ret = 0;

    /* send iorequest */
    /* Client sends a message to the server using the Tag-Matching API */
    request = ucp_tag_send_nb(ep, &length, sizeof(size_t),
                              ucp_dt_make_contig(1), TAG,
                              send_cb);

    status = request_wait(ucp_worker, request);
    if (status != UCS_OK){
        fprintf(stderr, "unable to %s UCX message (%s)\n",
                is_server ? "receive": "send", ucs_status_string(status));
        ret = -1;
    }

    printf("line:%d, send io request len:%zu\n", __LINE__, length);
    /* recv data*/
    recv_message = malloc(length + 1);
    request = ucp_tag_recv_nb(ucp_worker, recv_message, length,
                              ucp_dt_make_contig(1),
                              TAG, 0, tag_recv_cb);

    status = request_wait(ucp_worker, request);
    if (status != UCS_OK){
        fprintf(stderr, "unable to %s UCX message (%s)\n",
                is_server ? "receive": "send", ucs_status_string(status));
        ret = -1;
    }

    printf("line:%d, recv data:%s\n\n", __LINE__, recv_message);
    free(recv_message);

    /* recv ioresponse */
    recv_message = malloc(11);
    memset(recv_message, 0, 11);
    request = ucp_tag_recv_nb(ucp_worker, recv_message, 10,
                              ucp_dt_make_contig(1),
                              TAG, 0, tag_recv_cb);

    status = request_wait(ucp_worker, request);
    if (status != UCS_OK){
        fprintf(stderr, "unable to %s UCX message (%s)\n",
                is_server ? "receive": "send", ucs_status_string(status));
        ret = -1;
    }

    printf("line:%d, len:%s\n\n", __LINE__, recv_message);
    free(recv_message);

    return ret;
}

/**
 * Close the given endpoint.
 * Currently closing the endpoint with UCP_EP_CLOSE_MODE_FORCE since we currently
 * cannot rely on the client side to be present during the server's endpoint
 * closing process.
 */
static void ep_close(ucp_worker_h ucp_worker, ucp_ep_h ep)
{
    ucs_status_t status;
    void *close_req;

    close_req = ucp_ep_close_nb(ep, UCP_EP_CLOSE_MODE_FORCE);
    if (UCS_PTR_IS_PTR(close_req)) {
        do {
            ucp_worker_progress(ucp_worker);
            status = ucp_request_check_status(close_req);
        } while (status == UCS_INPROGRESS);

        ucp_request_free(close_req);
    } else if (UCS_PTR_STATUS(close_req) != UCS_OK) {
        fprintf(stderr, "failed to close ep %p\n", (void*)ep);
    }
}

/**
 * A callback to be invoked by UCX in order to initialize the user's request.
 */
static void request_init(void *request)
{
    test_req_t *req = request;
    req->complete = 0;
}

/**
 * Print this application's usage help message.
 */
static void usage()
{
    fprintf(stderr, "Usage: ucp_client_server [parameters]\n");
    fprintf(stderr, "UCP client-server example utility\n");
    fprintf(stderr, "\nParameters are:\n");
    fprintf(stderr, " -a Set IP address of the server "
                    "(required for client and should not be specified "
                    "for the server)\n");
    fprintf(stderr, " -l Set IP address where server listens "
                    "(If not specified, server uses INADDR_ANY; "
                    "Irrelevant at client)\n");
    fprintf(stderr, " -p Port number to listen/connect to (default = %d). "
                    "0 on the server side means select a random port and print it\n",
                    DEFAULT_PORT);
    fprintf(stderr, " -c Communication type for the client and server. "
                    " Valid values are:\n"
                    "     'stream' : Stream API\n"
                    "     'tag'    : Tag API\n"
                    "    If not specified, %s API will be used.\n", COMM_TYPE_DEFAULT);
    fprintf(stderr, "\n");
}

/**
 * Parse the command line arguments.
 */
static int parse_cmd(int argc, char *const argv[], char **server_addr,
                     char **listen_addr, send_recv_type_t *send_recv_type)
{
    int c = 0;
    int port;

    opterr = 0;

    while ((c = getopt(argc, argv, "a:l:p:c:")) != -1) {
        switch (c) {
        case 'a':
            *server_addr = optarg;
            break;
        case 'c':
            if (!strcasecmp(optarg, "stream")) {
                *send_recv_type = CLIENT_SERVER_SEND_RECV_STREAM;
            } else if (!strcasecmp(optarg, "tag")) {
                *send_recv_type = CLIENT_SERVER_SEND_RECV_TAG;
            } else {
                fprintf(stderr, "Wrong communication type %s. "
                        "Using %s as default\n", optarg, COMM_TYPE_DEFAULT);
                *send_recv_type = CLIENT_SERVER_SEND_RECV_DEFAULT;
            }
            break;
        case 'l':
            *listen_addr = optarg;
            break;
        case 'p':
            port = atoi(optarg);
            if ((port < 0) || (port > UINT16_MAX)) {
                fprintf(stderr, "Wrong server port number %d\n", port);
                return -1;
            }
            server_port = port;
            break;
        default:
            usage();
            return -1;
        }
    }

    return 0;
}

static int client_server_communication(ucp_worker_h worker, ucp_ep_h ep,
                                       send_recv_type_t send_recv_type,
                                       int is_server)
{
    int ret;

    /* Client-Server communication via Tag-Matching API */
    ret = send_recv_tag(worker, ep, is_server);

    /* Close the endpoint to the peer */
    ep_close(worker, ep);

    return ret;
}

/**
 * Create a ucp worker on the given ucp context.
 */
static int init_worker(ucp_context_h ucp_context, ucp_worker_h *ucp_worker)
{
    ucp_worker_params_t worker_params;
    ucs_status_t status;
    int ret = 0;

    memset(&worker_params, 0, sizeof(worker_params));

    worker_params.field_mask  = UCP_WORKER_PARAM_FIELD_THREAD_MODE;
    worker_params.thread_mode = UCS_THREAD_MODE_SINGLE;

    status = ucp_worker_create(ucp_context, &worker_params, ucp_worker);
    if (status != UCS_OK) {
        fprintf(stderr, "failed to ucp_worker_create (%s)\n", ucs_status_string(status));
        ret = -1;
    }

    return ret;
}

static int run_client(ucp_context_h ucp_context, ucp_worker_h ucp_worker,
                      char *server_addr, send_recv_type_t send_recv_type)
{
    ucp_ep_h     client_ep;
    ucs_status_t status;
    int          ret;

    status = start_client(ucp_worker, server_addr, &client_ep);
    if (status != UCS_OK) {
        fprintf(stderr, "failed to start client (%s)\n", ucs_status_string(status));
        ret = -1;
        goto out;
    }

    ret = client_server_communication(ucp_worker, client_ep, send_recv_type, 0);

out:
    return ret;
}

/**
 * Initialize the UCP context and worker.
 */
static int init_context(ucp_context_h *ucp_context, ucp_worker_h *ucp_worker)
{
    /* UCP objects */
    ucp_params_t ucp_params;
    ucs_status_t status;
    int ret = 0;

    memset(&ucp_params, 0, sizeof(ucp_params));

    /* UCP initialization */
    ucp_params.field_mask   = UCP_PARAM_FIELD_FEATURES     |
                              UCP_PARAM_FIELD_REQUEST_SIZE |
                              UCP_PARAM_FIELD_REQUEST_INIT;
    ucp_params.features     = UCP_FEATURE_STREAM | UCP_FEATURE_TAG;
    ucp_params.request_size = sizeof(test_req_t);
    ucp_params.request_init = request_init;

    status = ucp_init(&ucp_params, NULL, ucp_context);
    if (status != UCS_OK) {
        fprintf(stderr, "failed to ucp_init (%s)\n", ucs_status_string(status));
        ret = -1;
        goto err;
    }

    ret = init_worker(*ucp_context, ucp_worker);
    if (ret != 0) {
        goto err_cleanup;
    }

    return ret;

err_cleanup:
    ucp_cleanup(*ucp_context);
err:
    return ret;
}


int main(int argc, char **argv)
{
    send_recv_type_t send_recv_type = CLIENT_SERVER_SEND_RECV_DEFAULT;
    char *server_addr = NULL;
    char *listen_addr = NULL;
    int ret;

    /* UCP objects */
    ucp_context_h ucp_context;
    ucp_worker_h  ucp_worker;

    ret = parse_cmd(argc, argv, &server_addr, &listen_addr, &send_recv_type);
    if (ret != 0) {
        goto err;
    }

    /* Initialize the UCX required objects */
    ret = init_context(&ucp_context, &ucp_worker);
    if (ret != 0) {
        goto err;
    }

    /* Client-Server initialization */
    if (server_addr != NULL) {
       /* Client side */
        ret = run_client(ucp_context, ucp_worker, server_addr, send_recv_type);
    }

    ucp_worker_destroy(ucp_worker);
    ucp_cleanup(ucp_context);
err:
    return ret;
}
