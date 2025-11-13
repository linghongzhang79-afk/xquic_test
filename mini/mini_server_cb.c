/**
 * @file mini_server_cb.c contains callbacks definitions for mini_server, including:
 * 1. engine callbacks
 * 2. hq callbacks
 * 3. h3 callbacks
 */

#include "mini_server_cb.h"
#include <string.h>
#include <strings.h>
#include <sys/time.h>


#define XQC_MINI_SVR_MAX_STREAMS 16
#define SERVER_OUTPUT_FILE "server_received.txt"
/* engine callbacks */
typedef struct {
    int initialized;
    int generation;
    int expected_streams;
    size_t total_size;
    size_t total_received;
    int completed_streams;
    struct timeval earliest_start;
    struct timeval latest_end;
    unsigned char stream_done[XQC_MINI_SVR_MAX_STREAMS];
} xqc_mini_svr_file_state_t;

static xqc_mini_svr_file_state_t g_svr_file_state = {0};

static void xqc_mini_svr_reset_file_state(int stream_count, size_t total_size);
static int xqc_mini_svr_prepare_output_file(xqc_mini_svr_user_stream_t *user_stream);
static void xqc_mini_svr_mark_stream_complete(xqc_mini_svr_user_stream_t *user_stream);
static int xqc_mini_svr_time_cmp(const struct timeval *a, const struct timeval *b);
static double xqc_mini_svr_duration_ms(const struct timeval *start, const struct timeval *end);

static int
xqc_mini_svr_time_cmp(const struct timeval *a, const struct timeval *b)
{
    if (a->tv_sec < b->tv_sec) {
        return -1;
    }
    if (a->tv_sec > b->tv_sec) {
        return 1;
    }
    if (a->tv_usec < b->tv_usec) {
        return -1;
    }
    if (a->tv_usec > b->tv_usec) {
        return 1;
    }
    return 0;
}

static double
xqc_mini_svr_duration_ms(const struct timeval *start, const struct timeval *end)
{
    return (end->tv_sec - start->tv_sec) * 1000.0
        + (end->tv_usec - start->tv_usec) / 1000.0;
}


static void
xqc_mini_svr_reset_file_state(int stream_count, size_t total_size)
{
    if (stream_count <= 0) {
        stream_count = 1;
    }
    if (stream_count > XQC_MINI_SVR_MAX_STREAMS) {
        printf("[server] stream count %d exceeds limit %d, clamp\n",
            stream_count, XQC_MINI_SVR_MAX_STREAMS);
        stream_count = XQC_MINI_SVR_MAX_STREAMS;
    }

    g_svr_file_state.initialized = 1;
    g_svr_file_state.generation++;
    g_svr_file_state.expected_streams = stream_count;
    g_svr_file_state.total_size = total_size;
    g_svr_file_state.total_received = 0;
    g_svr_file_state.completed_streams = 0;
    g_svr_file_state.earliest_start.tv_sec = 0;
    g_svr_file_state.earliest_start.tv_usec = 0;
    g_svr_file_state.latest_end.tv_sec = 0;
    g_svr_file_state.latest_end.tv_usec = 0;
    memset(g_svr_file_state.stream_done, 0, sizeof(g_svr_file_state.stream_done));

    if (remove(SERVER_OUTPUT_FILE) == 0) {
        printf("[server] removed previous output file %s\n", SERVER_OUTPUT_FILE);
    }

    FILE *fp = fopen(SERVER_OUTPUT_FILE, "wb");
    if (fp == NULL) {
        perror("fopen");
        printf("[error] failed to prepare output file '%s'\n", SERVER_OUTPUT_FILE);
        return;
    }
    if (total_size > 0) {
        if (fseek(fp, (long)(total_size - 1), SEEK_SET) != 0) {
            perror("fseek");
        } else {
            fputc('\0', fp);
        }
    }
    fclose(fp);

    printf("[server] prepared output file '%s' for %d streams totaling %zu bytes\n",
        SERVER_OUTPUT_FILE, stream_count, total_size);
}

static int
xqc_mini_svr_prepare_output_file(xqc_mini_svr_user_stream_t *user_stream)
{
    if (!g_svr_file_state.initialized
        || g_svr_file_state.expected_streams != user_stream->stream_count
        || g_svr_file_state.total_size != user_stream->total_file_size) {
        xqc_mini_svr_reset_file_state(user_stream->stream_count,
            user_stream->total_file_size);
    }

    user_stream->file_generation = g_svr_file_state.generation;

    if (user_stream->recv_body_fp == NULL) {
        user_stream->recv_body_fp = fopen(SERVER_OUTPUT_FILE, "r+b");
        if (user_stream->recv_body_fp == NULL) {
            user_stream->recv_body_fp = fopen(SERVER_OUTPUT_FILE, "w+b");
        }
        if (user_stream->recv_body_fp == NULL) {
            perror("fopen");
            printf("[error] failed to open output file '%s'\n", SERVER_OUTPUT_FILE);
            return XQC_ERROR;
        }
    }

    return XQC_OK;
}

static void
xqc_mini_svr_mark_stream_complete(xqc_mini_svr_user_stream_t *user_stream)
{
    if (user_stream->stream_index < 0
        || user_stream->stream_index >= XQC_MINI_SVR_MAX_STREAMS) {
        return;
    }

    if (user_stream->file_generation != g_svr_file_state.generation) {
        return;
    }

    if (!g_svr_file_state.stream_done[user_stream->stream_index]) {
        g_svr_file_state.stream_done[user_stream->stream_index] = 1;
        g_svr_file_state.total_received += user_stream->recv_body_len;

        if (g_svr_file_state.completed_streams == 0) {
            g_svr_file_state.earliest_start = user_stream->start_time;
            g_svr_file_state.latest_end = user_stream->end_time;

        } else {
            if (xqc_mini_svr_time_cmp(&user_stream->start_time,
                    &g_svr_file_state.earliest_start) < 0) {
                g_svr_file_state.earliest_start = user_stream->start_time;
            }
            if (xqc_mini_svr_time_cmp(&user_stream->end_time,
                    &g_svr_file_state.latest_end) > 0) {
                g_svr_file_state.latest_end = user_stream->end_time;
            }
        }

        g_svr_file_state.completed_streams++;
        printf("[server] segment %d complete (%zu bytes at offset %zu)\n",
            user_stream->stream_index, user_stream->recv_body_len,
            user_stream->stream_offset);

        if (g_svr_file_state.completed_streams >= g_svr_file_state.expected_streams) {
            printf("[server] all %d segments received, assembled size %zu bytes\n",
                g_svr_file_state.expected_streams, g_svr_file_state.total_size);
            double duration_ms = xqc_mini_svr_duration_ms(&g_svr_file_state.earliest_start,
                &g_svr_file_state.latest_end);
            if (duration_ms > 0.0) {
                double mbps = (g_svr_file_state.total_received * 8.0)
                    / (duration_ms * 1000.0);
                printf("[server] aggregate throughput: %.3f Mbps over %.3f ms (%zu bytes)\n",
                    mbps, duration_ms, g_svr_file_state.total_received);
            } else {
                printf("[server] aggregate throughput unavailable (duration %.3f ms)\n",
                    duration_ms);
            }
        }
    }
}

const char *line_break = "\n";

/**
 * @brief engine callbacks to trigger engine main logic 
 */
void
xqc_mini_svr_engine_cb(int fd, short what, void *arg)
{
    xqc_mini_svr_ctx_t *ctx = (xqc_mini_svr_ctx_t *) arg;

    xqc_engine_main_logic(ctx->engine);
}

/**
 * @brief callbacks to set timer of engine callbacks
 */
void
xqc_mini_svr_set_event_timer(xqc_msec_t wake_after, void *arg)
{
    xqc_mini_svr_ctx_t *ctx = (xqc_mini_svr_ctx_t *)arg;

    struct timeval tv;
    tv.tv_sec = wake_after / 1000000;
    tv.tv_usec = wake_after % 1000000;
    event_add(ctx->ev_engine, &tv);
}

int
xqc_mini_svr_open_log_file(void *arg)
{
    xqc_mini_svr_ctx_t *ctx = (xqc_mini_svr_ctx_t*)arg;
    return open(ctx->args->env_cfg.log_path, (O_WRONLY | O_APPEND | O_CREAT), 0644);
}
void
xqc_mini_svr_write_log_file(xqc_log_level_t lvl, const void *buf, size_t size, void *arg)
{
    xqc_mini_svr_ctx_t *ctx = (xqc_mini_svr_ctx_t*)arg;
    if (ctx->log_fd <= 0) {
        return;
    }

    int write_len = write(ctx->log_fd, buf, size);
    if (write_len < 0) {
        printf("write log failed, errno: %d\n", get_sys_errno());
        return;
    }
    write_len = write(ctx->log_fd, line_break, 1);
    if (write_len < 0) {
        printf("write log failed, errno: %d\n", get_sys_errno());
    }
}


void
xqc_mini_svr_close_log_file(void *arg)
{
    xqc_mini_svr_ctx_t *ctx = (xqc_mini_svr_ctx_t*)arg;
    if (ctx->log_fd > 0) {
        close(ctx->log_fd);
        ctx->log_fd = 0;
    }
}

void
xqc_mini_svr_write_qlog_file(qlog_event_importance_t imp, const void *buf, size_t size, void *arg)
{
    xqc_mini_svr_ctx_t *ctx = (xqc_mini_svr_ctx_t*)arg;
    if (ctx->log_fd <= 0) {
        return;
    }

    int write_len = write(ctx->log_fd, buf, size);
    if (write_len < 0) {
        printf("write qlog failed, errno: %d\n", get_sys_errno());
        return;
    }
    write_len = write(ctx->log_fd, line_break, 1);
    if (write_len < 0) {
        printf("write qlog failed, errno: %d\n", get_sys_errno());
    }
}

int
xqc_mini_svr_open_keylog_file(void *arg)
{
    xqc_mini_svr_ctx_t *ctx = (xqc_mini_svr_ctx_t*)arg;
    return open(ctx->args->env_cfg.key_out_path, (O_WRONLY | O_APPEND | O_CREAT), 0644);
}

void
xqc_mini_svr_keylog_cb(const xqc_cid_t *scid, const char *line, void *arg)
{
    xqc_mini_svr_ctx_t *ctx = (xqc_mini_svr_ctx_t*)arg;
    if (ctx->keylog_fd <= 0) {
        printf("write keys error!\n");
        return;
    }

    int write_len = write(ctx->keylog_fd, line, strlen(line));
    if (write_len < 0) {
        printf("write keys failed, errno: %d\n", get_sys_errno());
        return;
    }
    write_len = write(ctx->keylog_fd, line_break, 1);
    if (write_len < 0) {
        printf("write keys failed, errno: %d\n", get_sys_errno());
    }
}

void
xqc_mini_svr_close_keylog_file(void *arg)
{
    xqc_mini_svr_ctx_t *ctx = (xqc_mini_svr_ctx_t*)arg;
    if (ctx->keylog_fd > 0) {
        close(ctx->keylog_fd);
        ctx->keylog_fd = 0;
    }
}
int
xqc_mini_svr_accept(xqc_engine_t *engine, xqc_connection_t *conn, const xqc_cid_t *cid,
    void *arg)
{
    DEBUG;

    return 0;
}


ssize_t 
xqc_mini_svr_write_socket(const unsigned char *buf, size_t size, const struct sockaddr *peer_addr,
    socklen_t peer_addrlen, void *arg)
{
    ssize_t res = XQC_OK;
    xqc_mini_svr_user_conn_t *user_conn = (xqc_mini_svr_user_conn_t *)arg;
    int fd = user_conn->ctx->current_fd;

    do {
        set_sys_errno(0);
        res = sendto(fd, buf, size, 0, peer_addr, peer_addrlen);
        if (res < 0) {
            printf("[error] xqc_mini_svr_write_socket err %zd %s, fd: %d\n", 
                res, strerror(get_sys_errno()), fd);
            if (get_sys_errno() == EAGAIN) {
                res = XQC_SOCKET_EAGAIN;
            }
        }
    } while ((res < 0) && (get_sys_errno() == EINTR));

    // printf("[report] xqc_mini_svr_write_socket success size=%lu\n", size);
    return res;
}

ssize_t
xqc_mini_svr_write_socket_ex(uint64_t path_id, const unsigned char *buf, size_t size, 
    const struct sockaddr *peer_addr,socklen_t peer_addrlen, void *conn_user_data)
{
    return xqc_mini_svr_write_socket(buf, size, peer_addr, peer_addrlen, conn_user_data);
}

void
xqc_mini_svr_conn_update_cid_notify(xqc_connection_t *conn, const xqc_cid_t *retire_cid,
    const xqc_cid_t *new_cid, void *user_data)
{
    DEBUG;
    // xqc_mini_svr_user_conn_t *user_conn = (xqc_mini_svr_user_conn_t *)user_data;
    // memcpy(&user_conn->cid, new_cid, sizeof(*new_cid));
}

/* h3 callbacks */
int
xqc_mini_svr_h3_conn_create_notify(xqc_h3_conn_t *h3_conn, const xqc_cid_t *cid,
    void *conn_user_data)
{
    DEBUG;
    xqc_mini_svr_user_conn_t *user_conn = (xqc_mini_svr_user_conn_t *)conn_user_data;
    xqc_h3_conn_set_user_data(h3_conn, user_conn);
    xqc_h3_conn_get_peer_addr(h3_conn, (struct sockaddr *)user_conn->peer_addr,
                              sizeof(struct sockaddr_in), &user_conn->peer_addrlen);
    memcpy(&user_conn->cid, cid, sizeof(*cid));

    g_svr_file_state.initialized = 0;
    g_svr_file_state.expected_streams = 0;
    g_svr_file_state.total_size = 0;
    g_svr_file_state.completed_streams = 0;
    memset(g_svr_file_state.stream_done, 0, sizeof(g_svr_file_state.stream_done));

    printf("[stats] xqc_mini_svr_h3_conn_create_notify \n");
    return 0;
}


int
xqc_mini_svr_h3_conn_close_notify(xqc_h3_conn_t *h3_conn, const xqc_cid_t *cid,
    void *conn_user_data)
{
    DEBUG;
    xqc_mini_svr_user_conn_t *user_conn = (xqc_mini_svr_user_conn_t*)conn_user_data;
    
    printf("[stats] xqc_mini_svr_h3_conn_close_notify success \n");
    return 0;
}


void 
xqc_mini_svr_h3_conn_handshake_finished(xqc_h3_conn_t *h3_conn, void *conn_user_data)
{
    DEBUG;
    xqc_mini_svr_user_conn_t *user_conn = (xqc_mini_svr_user_conn_t *)conn_user_data;
    xqc_conn_stats_t stats = xqc_conn_get_stats(user_conn->ctx->engine, &user_conn->cid);
}


int
xqc_mini_svr_h3_request_create_notify(xqc_h3_request_t *h3_request, void *strm_user_data)
{
    DEBUG;
    xqc_mini_svr_user_stream_t *user_stream = calloc(1, sizeof(*user_stream));
    user_stream->h3_request = h3_request;

    xqc_h3_request_set_user_data(h3_request, user_stream);
    user_stream->recv_buf = calloc(1, REQ_BUF_SIZE);

    printf("[stats] xqc_mini_svr_h3_request_create_notify success \n");
    return 0;
}

int
xqc_mini_svr_h3_request_close_notify(xqc_h3_request_t *h3_request, void *strm_user_data)
{
    DEBUG;
    xqc_request_stats_t stats = xqc_h3_request_get_stats(h3_request);
    printf("[stats] xqc_mini_svr_h3_request_close_notify success, cwnd_blocked:%"PRIu64"\n", stats.cwnd_blocked_ms);

    xqc_mini_svr_user_stream_t *user_stream = (xqc_mini_svr_user_stream_t*)strm_user_data;
    if (user_stream->recv_body_fp) {
        fclose(user_stream->recv_body_fp);
        user_stream->recv_body_fp = NULL;
    }
    free(user_stream->recv_buf);
    free(user_stream);

    return 0;
}
int
xqc_mini_cli_handle_h3_request(xqc_mini_svr_user_stream_t *user_stream)
{
    DEBUG;
    ssize_t ret = 0;

    /* response header buf list */
    xqc_http_header_t rsp_hdr[] = {
        {
            .name = {.iov_base = "content-type", .iov_len = 12},
            .value = {.iov_base = "text/plain", .iov_len = 10},
            .flags = 0,
        }
    };
    /* response header */
    xqc_http_headers_t rsp_hdrs;
    rsp_hdrs.headers = rsp_hdr;
    rsp_hdrs.count = sizeof(rsp_hdr) / sizeof(rsp_hdr[0]);

    if (user_stream->header_sent == 0) {
        ret = xqc_h3_request_send_headers(user_stream->h3_request, &rsp_hdrs, 0);
        if (ret < 0) {
            printf("[error] xqc_h3_request_send_headers error %zd\n", ret);
            return ret;
        } else {
            printf("[stats] xqc_h3_request_send_headers success \n");
            user_stream->header_sent = 1;
        }
    }

    ret = xqc_mini_svr_send_body(user_stream);
    return ret;
}

int
xqc_mini_svr_h3_request_read_notify(xqc_h3_request_t *h3_request, xqc_request_notify_flag_t flag,
    void *strm_user_data)
{
    DEBUG;
    int ret;
    char recv_buff[16384] = {0};
    ssize_t recv_buff_size, read, read_sum;
    unsigned char fin = 0;
    xqc_http_headers_t *headers = NULL;
    xqc_mini_svr_user_stream_t *user_stream = (xqc_mini_svr_user_stream_t *)strm_user_data;

    read = read_sum = 0;
    recv_buff_size = sizeof(recv_buff);
    
    
    
    /* recv headers */
    if (flag & XQC_REQ_NOTIFY_READ_HEADER) {
        headers = xqc_h3_request_recv_headers(h3_request, &fin);
        if (headers == NULL) {
            printf("[error] xqc_h3_request_recv_headers error\n");
            return XQC_ERROR;
        }
        int have_index = 0;
        int have_count = 0;
        int have_offset = 0;
        int have_total = 0;
        long parsed_index = 0;
        long parsed_count = 0;
        unsigned long long parsed_offset = 0;
        unsigned long long parsed_total = 0;

        printf("========== [server] Received HTTP/3 Request Headers ==========\n");
        for (size_t i = 0; i < headers->count; i++) {
            xqc_http_header_t *h = &headers->headers[i];
            printf("%.*s: %.*s\n",
                (int)h->name.iov_len, (char*)h->name.iov_base,
                (int)h->value.iov_len, (char*)h->value.iov_base);
            if (h->name.iov_len == strlen("content-length")
                && strncasecmp((char*)h->name.iov_base, "content-length",
                               h->name.iov_len) == 0) {
                char buf[64] = {0};
                size_t len = (h->value.iov_len < sizeof(buf) - 1)
                    ? h->value.iov_len : sizeof(buf) - 1;
                memcpy(buf, h->value.iov_base, len);
                buf[len] = '\0';

                unsigned long long content_length = strtoull(buf, NULL, 10);
                user_stream->expected_content_length = content_length;
                printf("[server] >>> Parsed Content-Length: %llu bytes\n", content_length);
                continue;
            }

            if (strncasecmp((char *)h->name.iov_base, "x-stream-index", h->name.iov_len) == 0) {
                char buf[32] = {0};
                size_t len = (h->value.iov_len < sizeof(buf) - 1)
                    ? h->value.iov_len : sizeof(buf) - 1;
                memcpy(buf, h->value.iov_base, len);
                buf[len] = '\0';
                parsed_index = strtol(buf, NULL, 10);
                have_index = 1;
                continue;
            }

            if (strncasecmp((char *)h->name.iov_base, "x-stream-count", h->name.iov_len) == 0) {
                char buf[32] = {0};
                size_t len = (h->value.iov_len < sizeof(buf) - 1)
                    ? h->value.iov_len : sizeof(buf) - 1;
                memcpy(buf, h->value.iov_base, len);
                buf[len] = '\0';
                parsed_count = strtol(buf, NULL, 10);
                have_count = 1;
                continue;
            }

            if (strncasecmp((char *)h->name.iov_base, "x-stream-offset", h->name.iov_len) == 0) {
                char buf[64] = {0};
                size_t len = (h->value.iov_len < sizeof(buf) - 1)
                    ? h->value.iov_len : sizeof(buf) - 1;
                memcpy(buf, h->value.iov_base, len);
                buf[len] = '\0';
                parsed_offset = strtoull(buf, NULL, 10);
                have_offset = 1;
                continue;
            }

            if (strncasecmp((char *)h->name.iov_base, "x-total-length", h->name.iov_len) == 0) {
                char buf[64] = {0};
                size_t len = (h->value.iov_len < sizeof(buf) - 1)
                    ? h->value.iov_len : sizeof(buf) - 1;
                memcpy(buf, h->value.iov_base, len);
                buf[len] = '\0';
                parsed_total = strtoull(buf, NULL, 10);
                have_total = 1;
                continue;
            }
        }
        printf("=============================================================\n");

        /* TODO: if recv headers once for all? */
        if (!have_index || !have_count || !have_offset || !have_total) {
            printf("[error] missing stream metadata headers\n");
            return XQC_ERROR;
        }


        if (parsed_count <= 0) {
            printf("[error] invalid stream count %ld\n", parsed_count);
            return XQC_ERROR;
        }
        if (parsed_index < 0 || parsed_index >= parsed_count) {
            printf("[error] invalid stream index %ld for count %ld\n",
                parsed_index, parsed_count);
            return XQC_ERROR;
        }

        user_stream->stream_index = (int)parsed_index;
        user_stream->stream_count = (int)parsed_count;
        user_stream->stream_offset = (size_t)parsed_offset;
        user_stream->total_file_size = (size_t)parsed_total;
        user_stream->metadata_parsed = 1;

        if (xqc_mini_svr_prepare_output_file(user_stream) != XQC_OK) {
            return XQC_ERROR;
        }

        printf("[server] stream %d/%d offset=%zu length=%zu total=%zu\n",
            user_stream->stream_index, user_stream->stream_count,
            user_stream->stream_offset, user_stream->expected_content_length,
            user_stream->total_file_size);

        user_stream->header_recvd = 1;

        gettimeofday(&user_stream->start_time, NULL);
    } 
    if (flag & XQC_REQ_NOTIFY_READ_BODY) {   /* recv body */
        if (!user_stream->metadata_parsed) {
            printf("[error] received body before metadata parsed\n");
            return XQC_ERROR;
        }

        if (user_stream->recv_body_fp == NULL) {
            if (xqc_mini_svr_prepare_output_file(user_stream) != XQC_OK) {
                return XQC_ERROR;
            }
        }
        do {
            read = xqc_h3_request_recv_body(h3_request, recv_buff, recv_buff_size, &fin);

            if (read == -XQC_EAGAIN) {
                break;

            } else if (read < 0) {
                printf("[error] xqc_h3_request_recv_body error %zd\n", read);
                return XQC_OK;
            }

            if (fseek(user_stream->recv_body_fp,
                    (long)(user_stream->stream_offset + user_stream->recv_body_len), SEEK_SET) != 0) {
                perror("fseek");
                return XQC_ERROR;
            }
            size_t written = fwrite(recv_buff, 1, (size_t)read, user_stream->recv_body_fp);
            if (written != (size_t)read) {
                perror("fwrite");
                return XQC_ERROR;
            }

            read_sum += read;
            user_stream->recv_body_len += read;
            //printf("[server] received chunk: %zd bytes (total: %zu)\n", read, user_stream->recv_body_len);
        } while (read > 0);
    }
    if (fin) {
        user_stream->fin_received = 1;
        gettimeofday(&user_stream->end_time, NULL);
        printf("[stats] read h3 request finish. total %zu bytes\n", user_stream->recv_body_len);
        
    }
    if (user_stream->fin_received &&
        user_stream->recv_body_len >= user_stream->expected_content_length) {

        if (user_stream->recv_body_fp) {
            fflush(user_stream->recv_body_fp);
            fclose(user_stream->recv_body_fp);
            user_stream->recv_body_fp = NULL;
        }
        double duration_ms = (user_stream->end_time.tv_sec - user_stream->start_time.tv_sec) * 1000.0 +
                         (user_stream->end_time.tv_usec - user_stream->start_time.tv_usec) / 1000.0;

        double mbps = (user_stream->recv_body_len * 8.0) / (duration_ms * 1000.0); // Mbps

        printf("[stats] Body finished. recv_len=%zu bytes, time=%.3f ms, speed=%.3f Mbps\n",
           user_stream->recv_body_len, duration_ms, mbps);
        xqc_mini_svr_mark_stream_complete(user_stream);
        xqc_mini_cli_handle_h3_request(user_stream);  
        
    }
    return 0;
}

int
xqc_mini_svr_send_body(xqc_mini_svr_user_stream_t *user_stream)
{
    int fin = 1, send_buf_size, ret;
    char send_buf[REQ_BUF_SIZE];

    send_buf_size = REQ_BUF_SIZE;
    memset(send_buf, 'D', send_buf_size);

    ret = xqc_h3_request_send_body(user_stream->h3_request, send_buf, send_buf_size, fin);
    
    printf("[reports] xqc_mini_svr_send_body success, size:%d \n", ret);
    return ret;
}

int
xqc_mini_svr_h3_request_write_notify(xqc_h3_request_t *h3_request, void *strm_user_data)
{
    DEBUG;
    xqc_mini_svr_user_stream_t *user_stream = (xqc_mini_svr_user_stream_t *)strm_user_data;
    int ret = xqc_mini_svr_send_body(user_stream);

    printf("[stats] write h3 request notify finish \n");
    return ret;
}
