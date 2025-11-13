/**
 * @file mini_server_cb.c contains callbacks definitions for mini_server, including:
 * 1. engine callbacks
 * 2. hq callbacks
 * 3. h3 callbacks
 */
#include "mini_client_cb.h"
/**
 * @brief engine callbacks to trigger engine main logic 
 */
const char *line_break = "\n";
void
xqc_mini_cli_engine_cb(int fd, short what, void *arg)
{
    xqc_mini_cli_ctx_t *ctx = (xqc_mini_cli_ctx_t *) arg;

    xqc_engine_main_logic(ctx->engine);
}

int
xqc_mini_cli_open_log_file(void *arg)
{
    xqc_mini_cli_ctx_t *ctx = (xqc_mini_cli_ctx_t*)arg;
    return open(ctx->args->env_cfg.log_path, (O_WRONLY | O_APPEND | O_CREAT), 0644);
}

void
xqc_mini_cli_close_log_file(void *arg)
{
    xqc_mini_cli_ctx_t *ctx = (xqc_mini_cli_ctx_t*)arg;
    if (ctx->log_fd > 0) {
        close(ctx->log_fd);
        ctx->log_fd = 0;
    }
}

void
xqc_mini_cli_write_log_file(xqc_log_level_t lvl, const void *buf, size_t size, void *engine_user_data)
{
    xqc_mini_cli_ctx_t *ctx = (xqc_mini_cli_ctx_t*)engine_user_data;
    if (ctx->log_fd <= 0) {
        return;
    }
    //printf("%s", (char *)buf);
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


int
xqc_mini_cli_open_keylog_file(void *arg)
{
    xqc_mini_cli_ctx_t *ctx = (xqc_mini_cli_ctx_t*)arg;
    return open(ctx->args->env_cfg.key_out_path, (O_WRONLY | O_APPEND | O_CREAT), 0644);
}

void
xqc_mini_cli_close_keylog_file(void *arg)
{
    xqc_mini_cli_ctx_t *ctx = (xqc_mini_cli_ctx_t*)arg;
    if (ctx->keylog_fd > 0) {
        close(ctx->keylog_fd);
        ctx->keylog_fd = 0;
    }
}

void
xqc_mini_cli_write_qlog_file(qlog_event_importance_t imp, const void *buf, size_t size, void *engine_user_data)
{
    xqc_mini_cli_ctx_t *ctx = (xqc_mini_cli_ctx_t*)engine_user_data;
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


void
xqc_mini_cli_keylog_cb(const xqc_cid_t *scid, const char *line, void *engine_user_data)
{
    xqc_mini_cli_ctx_t *ctx = (xqc_mini_cli_ctx_t*)engine_user_data;

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
int
xqc_mini_cli_h3_conn_create_notify(xqc_h3_conn_t *conn, const xqc_cid_t *cid, void *user_data)
{
    xqc_mini_cli_user_conn_t *user_conn = (xqc_mini_cli_user_conn_t *)user_data;

    user_conn->h3_conn = conn;
    memcpy(&user_conn->cid, cid, sizeof(xqc_cid_t));

    return XQC_OK;
}

int
xqc_mini_cli_h3_conn_close_notify(xqc_h3_conn_t *conn, const xqc_cid_t *cid, void *user_data)
{
    xqc_mini_cli_user_conn_t *user_conn = (xqc_mini_cli_user_conn_t *)user_data;

    event_base_loopbreak(user_conn->ctx->eb);
    printf("[stats] xqc_mini_cli_h3_conn_close_notify success \n");
    return XQC_OK;
}

void
xqc_mini_cli_h3_conn_handshake_finished(xqc_h3_conn_t *h3_conn, void *user_data)
{
    return;
}
int
xqc_mini_cli_h3_request_create_notify(xqc_h3_request_t *h3_request, void *h3s_user_data)
{
    return 0;
}

int
xqc_mini_cli_h3_request_close_notify(xqc_h3_request_t *h3_request, void *user_data)
{
    xqc_mini_cli_user_stream_t *user_stream = (xqc_mini_cli_user_stream_t *)user_data;
    xqc_mini_cli_user_conn_t *user_conn = user_stream->user_conn;
    xqc_mini_cli_ctx_t *conn_ctx = user_conn->ctx;
    xqc_request_stats_t stats = xqc_h3_request_get_stats(h3_request);

    if (user_stream->send_body_fp) {
        fclose(user_stream->send_body_fp);
        user_stream->send_body_fp = NULL;
    }
    if (user_stream->recv_body_fp) {
        fclose(user_stream->recv_body_fp);
        user_stream->recv_body_fp = NULL;
    }
    free(user_stream->send_buffer);
    user_stream->send_buffer = NULL;

    user_conn->completed_requests++;
    printf("[stats] stream %d close notify, completed %d/%d, cwnd_blocked:%"PRIu64"\n",
        user_stream->stream_index, user_conn->completed_requests,
        user_conn->target_requests, stats.cwnd_blocked_ms);

    if (user_conn->completed_requests >= user_conn->target_requests) {
        xqc_h3_conn_close(conn_ctx->engine, &user_conn->cid);
    }

    free(user_stream);

    //printf("[stats] xqc_mini_cli_h3_request_close_notify success, cwnd_blocked:%"PRIu64"\n", stats.cwnd_blocked_ms);
    return 0;
}
int
xqc_mini_cli_h3_request_read_notify(xqc_h3_request_t *h3_request, 
    xqc_request_notify_flag_t flag, void *h3s_user_data)
{
    char recv_buff[XQC_MAX_BUFF_SIZE] = {0};
    size_t recv_buff_size;
    ssize_t read, read_sum;
    unsigned char fin = 0;
    xqc_mini_cli_user_stream_t *user_stream = (xqc_mini_cli_user_stream_t *)h3s_user_data;
    xqc_mini_cli_user_conn_t *user_conn = user_stream->user_conn;

    if (flag & XQC_REQ_NOTIFY_READ_HEADER) {
        xqc_http_headers_t *headers;
        headers = xqc_h3_request_recv_headers(h3_request, &fin);
        if (headers == NULL) {
            printf("[error] xqc_h3_request_recv_headers error\n");
            return XQC_ERROR;
        }

        for (int i = 0; i < headers->count; i++) {
            printf("[receive report] %s = %s\n", (char *)headers->headers[i].name.iov_base,
                (char *)headers->headers[i].value.iov_base);
        }

        if (fin) {
            /* only header in request */
            user_stream->recv_fin = 1;
            printf("[stats] h3 request read header finish \n");
            return XQC_OK;
        }
    }

    /* continue to recv body */
    if (!(flag & XQC_REQ_NOTIFY_READ_BODY)) {
        return XQC_OK;
    }

    recv_buff_size = XQC_MAX_BUFF_SIZE;
    read = read_sum = 0;

    do {
        read = xqc_h3_request_recv_body(h3_request, recv_buff, recv_buff_size, &fin);
        if (read == -XQC_EAGAIN) {
            break;

        } else if (read < 0) {
            printf("xqc_h3_request_recv_body error %zd\n", read);
            return XQC_OK;
        }
    
        read_sum += read;
        user_stream->recv_body_len += read;
    } while (read > 0 && !fin);

    printf("[report] xqc_h3_request_recv_body size %zd, fin:%d\n", read, fin);

    if (fin) {
        printf("[stats] read h3 request finish. \n");
    }

    return XQC_OK;
}

int
xqc_mini_cli_h3_request_write_notify(xqc_h3_request_t *h3_request, void *h3s_user_data)
{
    int ret = 0;
    xqc_mini_cli_user_stream_t *user_stream = (xqc_mini_cli_user_stream_t *)h3s_user_data;
    
    ret = xqc_mini_cli_request_send(h3_request, user_stream);
    
    //printf("[stats] finish h3 request write notify!:%"PRIu64"\n", xqc_h3_stream_id(h3_request));
    
    return ret;
}

void
xqc_mini_cli_set_event_timer(xqc_usec_t wake_after, void *user_data)
{
    xqc_mini_cli_ctx_t *ctx = (xqc_mini_cli_ctx_t *) user_data;
    //printf("xqc_engine_wakeup_after %llu us, now %llu\n", wake_after, xqc_now());

    struct timeval tv;
    tv.tv_sec = wake_after / 1000000;
    tv.tv_usec = wake_after % 1000000;
    event_add(ctx->ev_engine, &tv);
}

ssize_t
xqc_mini_cli_write_socket(const unsigned char *buf, size_t size, const struct sockaddr *peer_addr,
    socklen_t peer_addrlen, void *conn_user_data)
{
    return xqc_mini_cli_write_socket_ex(0, buf, size, peer_addr, peer_addrlen, conn_user_data);
}

ssize_t
xqc_mini_cli_write_socket_ex(uint64_t path_id, const unsigned char *buf, size_t size,
    const struct sockaddr *peer_addr, socklen_t peer_addrlen, void *conn_user_data)
{
    int fd = -1;
    ssize_t res = 0;
    xqc_mini_cli_user_conn_t *user_conn = (xqc_mini_cli_user_conn_t *)conn_user_data;
    
    xqc_mini_cli_user_path_t *user_path = NULL;
    
    for (int i = 0; i < MAX_PATH_CNT; i++) {
        if (user_conn->paths[i].is_active && user_conn->paths[i].path_id == path_id) {
            user_path = &user_conn->paths[i];
            break;
        }
    }

    if (user_path == NULL) {
        user_path = &user_conn->paths[0];
    }

    if (user_path == NULL || !user_path->is_active || user_path->fd < 0) {
        return -1;
    }

    fd = user_path->fd;

    do {
        set_sys_errno(0);
        res = sendto(fd, buf, size, 0, peer_addr, peer_addrlen);
        if (res < 0) {
        
            // struct sockaddr_in *la = (struct sockaddr_in*)user_path->local_addr;
            // struct sockaddr_in *pa = (struct sockaddr_in*)user_path->peer_addr;
            // char local_ip[INET_ADDRSTRLEN];
            // char peer_ip[INET_ADDRSTRLEN];

            // inet_ntop(AF_INET, &la->sin_addr, local_ip, sizeof local_ip);
            // inet_ntop(AF_INET, &pa->sin_addr, peer_ip, sizeof peer_ip);

            //  printf("xqc_mini_cli_write_socket err %zd %s, fd: %d, path_id: %"PRIu64", address_path: %s,peer_address:%s\n",
            //      res, strerror(get_sys_errno()), fd, user_path->path_id,local_ip,peer_ip);
            
            if (get_sys_errno() == EAGAIN) {
                //user_conn->ctx->args->net_cfg.last_socket_time = xqc_now();
                res = XQC_SOCKET_EAGAIN;
            }
        }
    } while ((res < 0) && (get_sys_errno() == EINTR));

    // printf("[report] xqc_mini_cli_write_socket_ex success size=%lu\n", size);
    if (res >= 0) {
        user_conn->ctx->args->net_cfg.last_socket_time = xqc_now();
    }


    return res;
}

int
xqc_mini_cli_read_token(unsigned char *token, unsigned token_len)
{
    int fd = open(TOKEN_FILE, O_RDONLY);
    if (fd < 0) {
        return -1;
    }

    ssize_t n = read(fd, token, token_len);
    close(fd);
    return n;
}

void
xqc_mini_cli_save_token(const unsigned char *token, unsigned token_len, void *user_data)
{
    xqc_mini_cli_user_conn_t *user_conn = (xqc_mini_cli_user_conn_t *)user_data;
    printf("[stats] start xqc_mini_cli_save_token, use client ip as the key.\n");

    int fd = open(TOKEN_FILE, O_TRUNC | O_CREAT | O_WRONLY, 0666);
    if (fd < 0) {
        printf("save token error %s\n", strerror(get_sys_errno()));
        return;
    }

    ssize_t n = write(fd, token, token_len);
    if (n < token_len) {
        printf("save token error %s\n", strerror(get_sys_errno()));
        close(fd);
        return;
    }
    close(fd);
}

void
xqc_mini_cli_save_session_cb(const char * data, size_t data_len, void *user_data)
{
    xqc_mini_cli_user_conn_t *user_conn = (xqc_mini_cli_user_conn_t *)user_data;
    printf("[stats] start save_session_cb. \n");

    FILE * fp  = fopen(SESSION_TICKET_FILE, "wb");
    if (fp < 0) {
        printf("save session error %s\n", strerror(get_sys_errno()));
        return;
    }

    int write_size = fwrite(data, 1, data_len, fp);
    if (data_len != write_size) {
        printf("save _session_cb error\n");
        fclose(fp);
        return;
    }
    fclose(fp);
    return;
}


void
xqc_mini_cli_save_tp_cb(const char * data, size_t data_len, void * user_data)
{
    xqc_mini_cli_user_conn_t *user_conn = (xqc_mini_cli_user_conn_t *)user_data;
    printf("[stats] start save_tp_cb\n");

    FILE * fp = fopen(TRANSPORT_PARAMS_FILE, "wb");
    if (fp < 0) {
        printf("save transport callback error %s\n", strerror(get_sys_errno()));
        return;
    }

    int write_size = fwrite(data, 1, data_len, fp);
    if (data_len != write_size) {
        printf("save _tp_cb error\n");
        fclose(fp);
        return;
    }

    fclose(fp);
    return;
}


void
xqc_mini_cli_timeout_callback(int fd, short what, void *arg)
{
    int conn_timeout, ret;
    xqc_usec_t socket_idle_time;
    struct timeval tv;
    xqc_mini_cli_ctx_t *ctx;
    xqc_mini_cli_user_conn_t *user_conn;

    user_conn = (xqc_mini_cli_user_conn_t *)arg;
    ctx = user_conn->ctx;
    conn_timeout = ctx->args->net_cfg.conn_timeout;
    xqc_usec_t last_socket_time = ctx->args->net_cfg.last_socket_time;
    socket_idle_time = xqc_now() - last_socket_time;
    //printf("[stats] client connection idle time: %llu us, conn_timeout:%d,last_socket_time:%d\n", socket_idle_time,conn_timeout,last_socket_time);
    if (socket_idle_time < conn_timeout * 1000000) {
        tv.tv_sec = conn_timeout;
        tv.tv_usec = 0;
        event_add(user_conn->ev_timeout, &tv);
        return;
    }

conn_close:
    printf("[stats] client process timeout, connection closing... \n");
    ret = xqc_h3_conn_close(ctx->engine, &user_conn->cid);
    if (ret) {
        printf("[error] xqc_conn_close error:%d\n", ret);
        return;
    }
}

int
xqc_mini_cli_conn_create_notify(xqc_connection_t *conn, const xqc_cid_t *cid, void *user_data, void *conn_proto_data)
{
    DEBUG;

    xqc_mini_cli_user_conn_t *user_conn = (xqc_mini_cli_user_conn_t *) user_data;
    xqc_conn_set_alp_user_data(conn, user_conn);

    printf("[stats] xqc_conn_is_ready_to_send_early_data:%d\n", xqc_conn_is_ready_to_send_early_data(conn));
    return XQC_OK;
}