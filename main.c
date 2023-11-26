#include <err.h>
#include <limits.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <tls.h>

#include "j3g_http_parse.h"
#include "j3g_tls_parse.h"
#include "j3g_ja3_fingerprint.h"
#include "j3g_config.h"

pthread_mutex_t mutex_fd_array  = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t mutex_queue     = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t  cond_queue      = PTHREAD_COND_INITIALIZER;

enum j3g_error {
    J3GE_RDWR = -10,
    J3GE_INVHTTP = -9,
    J3GE_INVTLS = -8,
    J3GE_CONNECT = -7,
    J3GE_TLSCONN = -6,
    J3GE_TLSCONF = -5,
    J3GE_NOMEM = -4,
    J3GE_INVARGS = -3,
    J3GE_INVFD = -2,
    J3GE_INTMAX = -1,
    J3GE_OK = 0
};

struct j3g_worker_args {
    struct j3g_fd_vec       *fd_poll;
    struct j3g_fd_vec       *fd_node;
    struct tls              *ja3guard_tls_ctx;
    struct j3g_queue_head   *queue_head;
    int                      listen_fd;
};

struct j3g_fd_node {
    struct j3g_ja3   ja3;
    struct tls      *tls_ctx_ingress;
    struct tls      *tls_ctx_egress;
    int              fd_ingress;
    int              fd_egress;
    uint8_t          client_side: 1;
    uint8_t          http_established: 1;
};

struct j3g_queue_fd {
    struct pollfd               *pfd;
    TAILQ_ENTRY(j3g_queue_fd)    entries;
};

TAILQ_HEAD(j3g_queue_head, j3g_queue_fd);

struct j3g_fd_vec {
    void    *data;
    size_t   elem_size;
    int      capacity;
};

/*
 * cleaning and free the fd vector 'vec' created with j3g_fd_vec_init()
 */
void
j3g_fd_vec_clean(struct j3g_fd_vec *vec)
{
    if (vec == NULL)
        return;
    
    free(vec->data);
    (void)memset(vec, 0, sizeof(struct j3g_fd_vec));
}

/*
 * init a new fd vector with count item of elem_size size
 * return a copy of j3g_fd_vec
 *
 * User need to clean and free memory with the j3g_fd_vec_clean() function
 */
struct j3g_fd_vec
j3g_fd_vec_init(int count, size_t elem_size)
{
    struct j3g_fd_vec vec;
    
    (void)memset(&vec, 0, sizeof(struct j3g_fd_vec));
    
    if (count == 0)
        return vec;
    
    vec.capacity = count;
    vec.data = calloc(count, elem_size);
    vec.elem_size = elem_size;
    
    return vec;
}

/*
 * Unset the struct pollfd item according to the index/fd 'fd' inside 'vec'
 */
static int
_j3g_fd_vec_unset_pollfd(struct j3g_fd_vec *vec, int fd)
{
    struct pollfd *tmp;
    
    if (vec == NULL || vec->data == NULL)
        return J3GE_INVARGS;

    if (fd <= 0)
        return J3GE_INVFD;

    if (fd >= (INT_MAX - fd))
        return J3GE_INTMAX;

    if (fd >= vec->capacity)
        return J3GE_INVFD;

    tmp = vec->data;

    (void)memset(&tmp[fd], 0, sizeof(struct pollfd));

    return J3GE_OK;
}

/*
 * same as j3g_fd_vec_unset_pollfd() but use mutex for concurrency
 */
static int
_j3g_fd_vec_unset_pollfd_lock(struct j3g_fd_vec *vec, int fd)
{
    int ret;
    
    pthread_mutex_lock(&mutex_fd_array);
    
    ret = _j3g_fd_vec_unset_pollfd(vec, fd);
    
    pthread_mutex_unlock(&mutex_fd_array);
    
    return ret;
}

/*
 * Unset the struct j3g_fd_node item according to the index/fd 'fd' inside 'vec'
 */
static int
_j3g_fd_vec_unset_node(struct j3g_fd_vec *vec, int fd)
{
    struct j3g_fd_node *fd_array;
    
    if (vec == NULL || vec->data == NULL)
        return J3GE_INVARGS;
    
    if (fd <= 0)
        return J3GE_INVFD;
    
    if (fd >= (INT_MAX - fd))
        return J3GE_INTMAX;
    
    if (fd >= vec->capacity)
        return J3GE_INVFD;
    
    fd_array = vec->data;
    
    (void)memset(&fd_array[fd], 0, sizeof(struct j3g_fd_node));
    
    return J3GE_OK;
}

/*
 * same as _j3g_fd_vec_unset_node() but use mutex for concurrency
 */
static int
_j3g_fd_vec_unset_node_lock(struct j3g_fd_vec *vec, int fd)
{
    int ret;

    (void)pthread_mutex_lock(&mutex_fd_array);
    
    ret = _j3g_fd_vec_unset_node(vec, fd);

    (void)pthread_mutex_unlock(&mutex_fd_array);
    
    return ret;
}

/*
 * Get the pointer to item according to the index/fd 'fd'
 */
void *
j3g_fd_vec_get(struct j3g_fd_vec *vec, int fd)
{
    char *data_ptr;
    
    if (vec == NULL || vec->data == NULL)
        return NULL;
    
    if (fd <= 0)
        return NULL;
    
    if (fd >= (INT_MAX - fd))
        return NULL;
    
    if (fd >= vec->capacity)
        return NULL;
    
    data_ptr = vec->data;
    
    return &data_ptr[fd * vec->elem_size];
}

/*
 * same as j3g_fd_vec_get() but use mutex for concurrency
 */
void *
j3g_fd_vec_get_lock(struct j3g_fd_vec *vec, int fd)
{
    void *ptr;

    (void)pthread_mutex_lock(&mutex_fd_array);
    
    ptr = j3g_fd_vec_get(vec, fd);

    (void)pthread_mutex_unlock(&mutex_fd_array);
    
    return ptr;
}

/*
 * Set the new item pointed by 'elem' according to the fd 'fd' into the vector 'vec'
 * This function realloc automatically if more memory is needed
 *
 * return 0 for success
 */
int
j3g_fd_vec_set(struct j3g_fd_vec *vec, int fd, void *elem)
{
    char *data_ptr;
    void *tmp;
    size_t new_array_size;
    
    if (vec == NULL || vec->data == NULL)
        return J3GE_INVARGS;
    
    if (fd <= 0)
        return J3GE_INVFD;
    
    if (fd >= (INT_MAX - fd))
        return J3GE_INTMAX;
    
    if (fd >= vec->capacity) {
        new_array_size = ((fd + 1) * vec->elem_size);
        
        tmp = realloc(vec->data, new_array_size);
        
        if (tmp == NULL)
            return J3GE_NOMEM;
        
        vec->capacity = fd;
        vec->data = tmp;
    }
    
    data_ptr = vec->data;
    
    (void)memcpy(&data_ptr[fd * vec->elem_size], elem, vec->elem_size);
    //(void)memcpy(&vec->data[fd << 5], elem, vec->elem_size);
    
    return J3GE_OK;
}

/*
 * same as j3g_fd_vec_set() but use mutex for concurrency
 */
int
j3g_fd_vec_set_lock(struct j3g_fd_vec *vec, int fd, void *elem)
{
    int ret;
    
    pthread_mutex_lock(&mutex_fd_array);
    
    ret = j3g_fd_vec_set(vec, fd, elem);
    
    pthread_mutex_unlock(&mutex_fd_array);
    
    return ret;
}

/*
 * insert new struct pollfd element into the queue 'head'
 */
int
j3g_queue_insert(struct j3g_queue_head *head, struct pollfd *pfd)
{
    struct j3g_queue_fd *new;

    pthread_mutex_lock(&mutex_queue);
    
    new = malloc(sizeof(struct j3g_queue_fd));
    if (new == NULL)
        return J3GE_NOMEM;

    new->pfd = pfd;

    TAILQ_INSERT_TAIL(head, new, entries);

    pthread_mutex_unlock(&mutex_queue);

    return J3GE_OK;
}

/*
 * pop (get and remove) the first element inside the queue 'head'
 * This function "block" when the queue is empty
 *
 * return pointer to the struct pollfd element.
 */
struct pollfd *
j3g_queue_pop(struct j3g_queue_head *head)
{
    struct j3g_queue_fd *tmp;
    
    pthread_mutex_lock(&mutex_queue);
    
    while (TAILQ_EMPTY(head))
        pthread_cond_wait(&cond_queue, &mutex_queue);
    
    tmp = TAILQ_FIRST(head);
    
    if (tmp == NULL)
        return NULL;
    
    TAILQ_REMOVE(head, tmp, entries);
    
    pthread_mutex_unlock(&mutex_queue);
    
    return tmp->pfd;
}

/*
 * Accept a new client (TCP connection)
 */
static void
_worker_accept(struct j3g_worker_args *args)
{
    struct pollfd pfd;
    struct sockaddr_in cli;
    int client_fd;
    socklen_t addr_len;

    addr_len = sizeof(struct sockaddr_in);
    
    client_fd = accept(args->listen_fd, (struct sockaddr *)&cli, &addr_len);

    pfd.fd = client_fd;
    pfd.events = POLLIN;

    /*
     * if accept() don't return an error
     * then set the followed pollfd into the fd vector for polling
     */
    if (client_fd > 0)
        (void)j3g_fd_vec_set_lock(args->fd_poll, client_fd, &pfd);
}

/*
 * Parsing the TLS request from the client and store information into 'tls_hello'
 *
 * return 0 for success
 */
static int
_worker_parse_tls(const unsigned char *data, size_t size, struct j3g_tls_client_hello *tls_hello)
{
    struct j3g_tls_record tls_record;
    struct j3g_tls_handshake tls_handshake;
    int ret;
    
    ret = j3g_tls_traverse_record(&tls_record, (const unsigned char *)data, size);
    if (ret != 0) return ret;
    
    ret = j3g_tls_traverse_handshake(&tls_handshake, &tls_record);
    if (ret != 0) return ret;
    
    ret = j3g_tls_traverse_client_hello(tls_hello, &tls_handshake);
    
    return ret;
}

/*
 * Write 'len' byte of 'buf' to the corresponding egress fd/context of 'node'
 * using tls_write() if node use TLS otherwise just use write()
 *
 * return the numbers of bytes send to egress
 */
static size_t
_worker_write_data(struct j3g_fd_node *node, const char *buf, size_t len)
{
    if (node->tls_ctx_egress != NULL)
        len = tls_write(node->tls_ctx_egress, buf, len);
    else
        len = write(node->fd_egress, buf, len);

    return len;
}

static ssize_t
_worker_read_data(struct j3g_fd_node *node, char *buf, size_t size)
{
    ssize_t len;

    if (node->tls_ctx_ingress)
        len = tls_read(node->tls_ctx_ingress, buf, size);
    else
        len = read(node->fd_ingress, buf, size);

    return len;
}

/*
 * close the connection of fd and its corresponding egress fd
 *
 * return 0 for success
 */
static int
_worker_close_conn(struct j3g_worker_args *args, int fd)
{
    struct j3g_fd_node *node;
    struct j3g_fd_node *egress_node;

    node = j3g_fd_vec_get_lock(args->fd_node, fd);

    if (node == NULL || node->fd_ingress <= 0)
        return J3GE_INVARGS;
    
    /*
     * if node found, get the corresponding egress side and close/clean them
     */
    if (node->fd_ingress > 0) {
        egress_node = j3g_fd_vec_get_lock(args->fd_node, node->fd_egress);

        if (node->client_side == 0 && egress_node->fd_ingress > 0) {
            (void)tls_close(egress_node->tls_ctx_ingress);
            (void)close(egress_node->fd_ingress);
        }

        (void)_j3g_fd_vec_unset_pollfd_lock(args->fd_poll, egress_node->fd_ingress);
        (void)_j3g_fd_vec_unset_node_lock(args->fd_node, egress_node->fd_ingress);
    }

    (void)close(fd);
    
    /* modify the fd inside the dynamic array for setting fd to 0 and disable polling for it */
    (void)_j3g_fd_vec_unset_node_lock(args->fd_node, fd);
    (void)_j3g_fd_vec_unset_pollfd_lock(args->fd_poll, fd);
    
    return J3GE_OK;
}

/*
 * Create a new connection to the endpoint and update 'node_cli'
 *
 * return 0 for success.
 */
static int
_worker_init_endpoint_conn(struct j3g_worker_args *args, struct j3g_fd_node *node_cli)
{
    struct pollfd pfd;
    struct sockaddr_in sockaddr_endpoint;
    struct tls *tls_ctx_endpoint;
    struct tls_config *config;
    int fd_endpoint;
    int ret;
    struct j3g_fd_node endpoint_node;
    
    tls_ctx_endpoint = tls_client();
    config = tls_config_new();

    /* to delete after test */
    tls_config_insecure_noverifycert(config);
    tls_config_insecure_noverifyname(config);
    tls_config_insecure_noverifytime(config);
    /* ******************** */

    (void)tls_config_set_ca_file(config, j3g_global_config.endpoint.tls_ca_file);
    (void)tls_config_set_cert_file(config, j3g_global_config.endpoint.tls_auth_cert_file);
    (void)tls_config_set_key_file(config, j3g_global_config.endpoint.tls_auth_key_file);

    if (tls_configure(tls_ctx_endpoint, config) < 0) {
        (void)tls_config_free(config);

        return J3GE_TLSCONF;
    }

    (void)tls_config_free(config);
 
    sockaddr_endpoint.sin_family = AF_INET;
    sockaddr_endpoint.sin_port = htons(j3g_global_config.endpoint.port);
    sockaddr_endpoint.sin_addr.s_addr = inet_addr(j3g_global_config.endpoint.ip_addr);
    
    fd_endpoint = socket(AF_INET, SOCK_STREAM, 0);

    if (fd_endpoint < 0)
        return J3GE_INVFD;
    
    ret = connect(fd_endpoint, (struct sockaddr *)&sockaddr_endpoint, sizeof(struct sockaddr));
    
    if (ret == -1)
        return J3GE_CONNECT;
    
    if (j3g_global_config.endpoint.use_tls) {
        ret = tls_connect_socket(tls_ctx_endpoint, fd_endpoint, j3g_global_config.endpoint.servername);

        if (ret == -1) {
            _worker_close_conn(args, node_cli->fd_ingress);
            return J3GE_TLSCONN;
        }

        node_cli->tls_ctx_egress = tls_ctx_endpoint;
        endpoint_node.tls_ctx_ingress = tls_ctx_endpoint;
    }
    
    /* updating the node of the client */
    node_cli->fd_egress = fd_endpoint;
    
    /* adding the fd (socket) of the endpoint to the dynamic array for polling */
    pfd.fd = fd_endpoint;
    pfd.events = POLLIN;

    (void)j3g_fd_vec_set_lock(args->fd_poll, fd_endpoint, &pfd);
  
    endpoint_node.client_side = 0;
    endpoint_node.http_established = 0;
    endpoint_node.fd_egress = node_cli->fd_ingress;
    endpoint_node.fd_ingress = fd_endpoint;
    endpoint_node.tls_ctx_egress = node_cli->tls_ctx_ingress;

    /* adding the endpoint node into the hash map */
    (void)j3g_fd_vec_set_lock(args->fd_node, endpoint_node.fd_ingress, &endpoint_node);

    return J3GE_OK;
}

/*
 * Handle the first connection of the client 'fd':
 * Parse and accept the TLS handshake
 * Generate the Ja3 fingerprint
 *
 * return 0 for success
 */
static int
_worker_recv_first_conn(struct j3g_worker_args *args, int fd)
{
    struct j3g_tls_client_hello tls_hello;
    struct j3g_fd_node node_cli;
    struct j3g_ja3 ja3;
    struct tls *tls_ctx_cli;
    int ret;
    char buf[2000];
    ssize_t len;
    
    len = recv(fd, buf, 2000, MSG_PEEK);
    
    if (len < 0)
        return J3GE_INVARGS;
    
    ret = _worker_parse_tls((const unsigned char *)buf, 2000, &tls_hello);
    
    if (ret != 0) {
        (void) _worker_close_conn(args, fd);
        return J3GE_INVTLS;
    }

    ret = j3g_ja3_fingerprint(&ja3, &tls_hello);
    
    if (ret != 0) {
        (void) _worker_close_conn(args, fd);
        return J3GE_INVTLS;
    }

    if (tls_accept_socket(args->ja3guard_tls_ctx, &tls_ctx_cli, fd) != 0) {
        (void)_worker_close_conn(args, fd);
        return J3GE_TLSCONN;
    }
    
    node_cli.http_established = 0;
    node_cli.client_side = 1;
    node_cli.fd_ingress = fd;
    node_cli.tls_ctx_ingress = tls_ctx_cli;
    node_cli.ja3 = ja3;
    
    ret = _worker_init_endpoint_conn(args, &node_cli);
    
    if (ret != 0) {
        _worker_close_conn(args, fd);
        return ret;
    }
    
    /* adding the node of the client into the hash map */
    (void)j3g_fd_vec_set_lock(args->fd_node, node_cli.fd_ingress, &node_cli);
    
    return J3GE_OK;
}

static int
_worker_recv(struct j3g_worker_args *args, int fd)
{
    struct j3g_fd_node *node;
    struct pollfd *pfd;
    int ret;
    int i;
    char buf[2000];
    ssize_t len;

    node = j3g_fd_vec_get_lock(args->fd_node, fd);

    if (node == NULL)
        return J3GE_INVARGS;

    pfd = j3g_fd_vec_get_lock(args->fd_poll, fd);

    if (pfd == NULL)
        return J3GE_INVFD;
    
    if (pfd->revents & POLLHUP) {
        (void)_worker_close_conn(args, fd);
        return J3GE_OK;
    }
    
    /* no entry, client not established yet */
    if (node->fd_ingress == 0) {
        ret = _worker_recv_first_conn(args, fd);
        
        if (ret != 0) {
            (void)_worker_close_conn(args, fd);
            return ret;
        }

  
    /* client are already connected to the endpoint */
    } else {
        struct j3g_fd_node *endpoint_node;
        struct j3g_http http;
        char httpbuf[2000];
        size_t httplen;

        len = _worker_read_data(node, buf, sizeof(buf));

        if (len < 0) {
            (void)_worker_close_conn(args, fd);
            return J3GE_RDWR;
        }
        
        /* node exist so endpoint connexion is done but no http established 
         * and if is client_side node
         */
        if (node->client_side && node->http_established == 0) {
            ret = j3g_http_parser(&http, (const char *)buf, len);
            
            if (ret != 0) {
                j3g_http_cleanup(&http);
                (void)_worker_close_conn(args, fd);
                return J3GE_INVHTTP;
            }

            for (i = 0; i < j3g_global_config.http.custom_headers_len; i++) {
                j3g_http_headers_insert(&http,
                                        j3g_global_config.http.custom_headers[i].key,
                                        j3g_global_config.http.custom_headers[i].value);

            }

            if (j3g_global_config.http.x_ja3_text)
                j3g_http_headers_insert(&http, "X-Ja3-Text:", node->ja3.full_string);

            if (j3g_global_config.http.x_ja3_hash)
                j3g_http_headers_insert(&http, "X-Ja3-Hash:", (const char *)node->ja3.md5);

            httplen = j3g_http_total_size(&http);

            if (httplen > sizeof(httpbuf)) {
                j3g_http_cleanup(&http);
                (void)_worker_close_conn(args, fd);

                return J3GE_NOMEM;
            }

            j3g_http_build_request(&http, httpbuf, sizeof(httpbuf));
            j3g_http_cleanup(&http);

            if (_worker_write_data(node, httpbuf, httplen) <= 0)
                (void)_worker_close_conn(args, fd);

            node->http_established = 1;
            
            /* get node of endpoint */
            endpoint_node = j3g_fd_vec_get_lock(args->fd_node, node->fd_egress);
            
            if (endpoint_node == NULL) {
                (void)_worker_close_conn(args, fd);
                return J3GE_INVFD;
            }
            
            endpoint_node->http_established = 1;
    
        /* if is already established http connexion regardless of client or endpoint side 
         * just write the data read to the corresponding egress context
         */
        } else if (node->http_established == 1) {
            if (_worker_write_data(node, buf, len) < 0) {
                (void)_worker_close_conn(args, fd);
                return J3GE_RDWR;
            }
        }
    }
    
    return J3GE_OK;
}

void *
worker(void *args)
{
    struct pollfd *pfd;
    struct j3g_worker_args *data;
    
    data = (struct j3g_worker_args *)args;
    
    while (1) {
        pfd = j3g_queue_pop(data->queue_head);
        
        if (pfd == NULL)
            errx(EXIT_FAILURE, "Fatal error");

        /*
         * socket are closed (by client or endpoint)
         */
        if (pfd->revents & POLLHUP) {
            (void)_worker_close_conn(args, pfd->fd);
            continue;
        }
        
        /*
         * if the fd pop'd is the fd used by listen() its mean a new client has connected
         * so accept its tcp session
         */
        if (pfd->fd == data->listen_fd) {
            _worker_accept(data);
        } else {
            (void)_worker_recv(args, pfd->fd);
        }
    }
    
    return NULL;
}

int
main(void)
{
    struct tls_config *ja3guard_tls_cfg = NULL;
    struct tls *ja3guard_tls_ctx = NULL;
    struct sockaddr_in serv;
    struct j3g_worker_args worker_args;
    struct j3g_fd_vec array_pfd;
    struct j3g_fd_vec array_node;
    struct pollfd pfd;
    struct j3g_queue_head queue_head;
    socklen_t addr_len;
    uint32_t protocol_tls;
    pthread_t *tid_array;
    int ja3guard_fd;
    int i;
    int reuseaddr_opt;
    int ret;
    char errmsg[200];
    
    addr_len = sizeof(struct sockaddr);
    tid_array = NULL;

    TAILQ_INIT(&queue_head);
    
    ret = j3g_config_parse("example_config.toml", errmsg, 200);
    if (ret != J3G_CONFE_OK)
        errx(EXIT_FAILURE, "j3g_config_parse(): %s", errmsg);

    if (j3g_global_config.ja3.workers <= 0 || (INT_MAX - j3g_global_config.ja3.workers) == 0)
        errx(EXIT_FAILURE, "ja3.workers need to be greater than 0 and lower than %d", INT_MAX);
    
    ja3guard_fd = socket(AF_INET, SOCK_STREAM, 0);

    if (ja3guard_fd < 0)
        errx(EXIT_FAILURE, "socket(): %s", strerror(-ja3guard_fd));

    serv.sin_family = AF_INET;
    serv.sin_port = htons(j3g_global_config.ja3.listen_port);
    serv.sin_addr.s_addr = inet_addr(j3g_global_config.ja3.listen_addr);

    reuseaddr_opt = 1;
    if (setsockopt(ja3guard_fd, SOL_SOCKET, SO_REUSEADDR, &reuseaddr_opt, sizeof(reuseaddr_opt)) == -1)
        err(EXIT_FAILURE, "setsockopt()");

    ja3guard_tls_cfg = tls_config_new();

    (void)tls_config_parse_protocols(&protocol_tls, j3g_global_config.ja3.tls_version);
    (void)tls_config_set_protocols(ja3guard_tls_cfg, protocol_tls);
    (void)tls_config_set_key_file(ja3guard_tls_cfg, j3g_global_config.ja3.tls_key_file);
    (void)tls_config_set_cert_file(ja3guard_tls_cfg, j3g_global_config.ja3.tls_cert_file);
    (void)tls_config_set_alpn(ja3guard_tls_cfg, "http/1.1");
    
    ja3guard_tls_ctx = tls_server();

    if (tls_configure(ja3guard_tls_ctx, ja3guard_tls_cfg) != 0)
        errx(EXIT_FAILURE, "tls_configure: %s", tls_config_error(ja3guard_tls_cfg));
    
    if (bind(ja3guard_fd, (struct sockaddr *)&serv, addr_len) != 0)
        err(EXIT_FAILURE, "bind()");

    if (listen(ja3guard_fd, (int)j3g_global_config.ja3.workers) != 0)
        err(EXIT_FAILURE, "listen()");
    
    array_pfd = j3g_fd_vec_init(1024, sizeof(struct pollfd));
    
    if (array_pfd.data == NULL)
        err(EXIT_FAILURE, "j3g_fd_vec_init()");
    
    array_node = j3g_fd_vec_init(1024, sizeof(struct j3g_fd_node));
    
    if (array_node.data == NULL)
        err(EXIT_FAILURE, "j3g_fd_vec_init()");

    pfd.fd = ja3guard_fd;
    pfd.events = POLLIN;
    
    (void)j3g_fd_vec_set_lock(&array_pfd, ja3guard_fd, &pfd);
    
    worker_args.ja3guard_tls_ctx = ja3guard_tls_ctx;
    worker_args.fd_poll = &array_pfd;
    worker_args.queue_head = &queue_head;
    worker_args.listen_fd = ja3guard_fd;
    worker_args.fd_node = &array_node;
    
    tid_array = calloc(j3g_global_config.ja3.workers, sizeof(pthread_t));
    
    if (tid_array == NULL)
        err(EXIT_FAILURE, "calloc()");
    
    for (i = 0; i < j3g_global_config.ja3.workers; i++) {
        ret = pthread_create(&tid_array[i], NULL, worker, &worker_args);
        if (ret != 0)
            errx(EXIT_FAILURE, "pthread_create(): %s", strerror(ret));
    }

    while (1) {
        struct pollfd *pfd_ptr;
        int nb_ready;
        
        pfd_ptr = array_pfd.data;
        
        /* don't poll the 3 first element because their correspond to STDIN, STDOUT and STDERR */
        nb_ready = poll(&pfd_ptr[3], (array_pfd.capacity - 3), 0);

        if (nb_ready > 0) {
            for (i = 3; i < (array_pfd.capacity - 3); i++) {
                if (pfd_ptr[i].revents & (POLLIN | POLLHUP)) {
                    (void) j3g_queue_insert(&queue_head, &pfd_ptr[i]);
                }
            }
        }

        (void)pthread_cond_broadcast(&cond_queue);
        usleep(50000);
    }

cleanup:
    j3g_fd_vec_clean(&array_pfd);
    free(tid_array);

    (void)tls_close(ja3guard_tls_ctx);
    (void)tls_free(ja3guard_tls_ctx);
    (void)tls_config_free(ja3guard_tls_cfg);
    (void)close(ja3guard_fd);
    
    return 0;
}