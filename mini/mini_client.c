#include "mini_client.h"
#include <inttypes.h>
#include <netdb.h>

#define CHUNK_SIZE (4 * 1024)


static void xqc_mini_cli_conn_ready_to_create_path(const xqc_cid_t *cid, void *conn_user_data);
static void xqc_mini_cli_path_removed(const xqc_cid_t *cid, uint64_t path_id, void *conn_user_data);
static int xqc_mini_cli_parse_cmd_args(xqc_mini_cli_args_t *args, int argc, char *argv[]);
static void xqc_mini_cli_dump_path_bindings(xqc_mini_cli_user_conn_t *user_conn);
static int xqc_mini_cli_prepare_user_path(xqc_mini_cli_user_conn_t *user_conn,
    xqc_mini_cli_user_path_t *path);
static xqc_mini_cli_user_path_t *xqc_mini_cli_find_inactive_path(xqc_mini_cli_user_conn_t *user_conn);
static int xqc_mini_cli_get_target_path_count(xqc_mini_cli_user_conn_t *user_conn);
static int xqc_mini_cli_bind_to_interface(int fd, const char *interface_name, int family);
static int xqc_mini_cli_set_local_addr(xqc_mini_cli_user_path_t *path);
static void xqc_mini_cli_format_addr_port(const struct sockaddr *addr, socklen_t addrlen,
    char *buf, size_t buflen);

//引擎的ssl配置：这里应该是加密所使用算法和组别
void
xqc_mini_cli_init_engine_ssl_config(xqc_engine_ssl_config_t *ssl_cfg, xqc_mini_cli_args_t *args)
{
    ssl_cfg->ciphers = args->quic_cfg.ciphers;
    ssl_cfg->groups = args->quic_cfg.groups;
}


void
xqc_mini_cli_init_callback(xqc_engine_callback_t *cb, xqc_transport_callbacks_t *tcb, xqc_mini_cli_args_t *args)
{
    static xqc_engine_callback_t callback = {
        .set_event_timer = xqc_mini_cli_set_event_timer,
        .log_callbacks = {
            .xqc_log_write_err = xqc_mini_cli_write_log_file,
            .xqc_log_write_stat = xqc_mini_cli_write_log_file,
            .xqc_qlog_event_write = xqc_mini_cli_write_qlog_file
        },
        .keylog_cb = xqc_mini_cli_keylog_cb,
    };

    static xqc_transport_callbacks_t transport_cbs = {
        .write_socket = xqc_mini_cli_write_socket,
        .write_socket_ex = xqc_mini_cli_write_socket_ex,
        .save_token = xqc_mini_cli_save_token,
        .save_session_cb = xqc_mini_cli_save_session_cb,
        .save_tp_cb = xqc_mini_cli_save_tp_cb,
        .ready_to_create_path_notify = xqc_mini_cli_conn_ready_to_create_path,
        .path_removed_notify = xqc_mini_cli_path_removed,
    };

    *cb = callback;
    *tcb = transport_cbs;
}
//对应教程里面的engine的初始化
int
xqc_mini_cli_init_xquic_engine(xqc_mini_cli_ctx_t *ctx, xqc_mini_cli_args_t *args)
{
    int ret;
    xqc_config_t egn_cfg;
    xqc_engine_callback_t callback;
    xqc_engine_ssl_config_t ssl_cfg = {0};
    xqc_transport_callbacks_t transport_cbs;
    
    /* get default parameters of xquic engine */
    ret = xqc_engine_get_default_config(&egn_cfg, XQC_ENGINE_CLIENT);
    if (ret < 0) {
        return XQC_ERROR;
    }

    /* init ssl config */
    xqc_mini_cli_init_engine_ssl_config(&ssl_cfg, args);

    /* init engine & transport callbacks */
    xqc_mini_cli_init_callback(&callback, &transport_cbs, args);

    /* create client engine */
    ctx->engine = xqc_engine_create(XQC_ENGINE_CLIENT, &egn_cfg, &ssl_cfg,
                                    &callback, &transport_cbs, ctx);
    if (ctx->engine == NULL) {
        printf("[error] xqc_engine_create error\n");
        return XQC_ERROR;
    }

    ctx->ev_engine = event_new(ctx->eb, -1, 0, xqc_mini_cli_engine_cb, ctx);
    return XQC_OK;
}
//转输入地址和端口为sockaddr_in
void
xqc_mini_cli_convert_text_to_sockaddr(int type,
    const char *addr_text, unsigned int port,
    struct sockaddr **saddr, socklen_t *saddr_len)
{
    *saddr = calloc(1, sizeof(struct sockaddr_in));
    struct sockaddr_in *addr_v4 = (struct sockaddr_in *)(*saddr);
    inet_pton(type, addr_text, &(addr_v4->sin_addr.s_addr));
    
    addr_v4->sin_family = type;
    addr_v4->sin_port = htons(port);
    *saddr_len = sizeof(struct sockaddr_in);
    
}

void
xqc_mini_cli_init_args(xqc_mini_cli_args_t *args)
{
    /* init network args */
    args->net_cfg.conn_timeout = 9;
    args->net_cfg.multi_interface_cnt = 0;
    for (int i = 0; i < MAX_PATH_CNT; i++) {
        memset(args->net_cfg.multi_interface[i], 0, sizeof(args->net_cfg.multi_interface[i]));
    }
    /**
     * init quic config
     * it's recommended to replace the constant value with option arguments according to actual needs
     * XQC_TLS_CIPHERS和XQC_TLS_GROUPS对应加密算法，在xquic.h里面
     * 这里的设置多路径调度算法为minrtt
     */
    strncpy(args->quic_cfg.ciphers, XQC_TLS_CIPHERS, CIPHER_SUIT_LEN - 1);
    strncpy(args->quic_cfg.groups, XQC_TLS_GROUPS, TLS_GROUPS_LEN - 1);
    args->quic_cfg.multipath = 1;
    strncpy(args->quic_cfg.mp_sched, "balanced", sizeof(args->quic_cfg.mp_sched));
    args->quic_cfg.cc = CC_TYPE_BBR;


    /* init environmen args */
    // args->env_cfg.log_level = XQC_LOG_DEBUG;
    //定义了输出的日志相关内容
    strncpy(args->env_cfg.log_path, LOG_PATH, sizeof(args->env_cfg.log_path));
    strncpy(args->env_cfg.out_file_dir, OUT_DIR, sizeof(args->env_cfg.out_file_dir));
    strncpy(args->env_cfg.key_out_path, KEY_PATH, sizeof(args->env_cfg.key_out_path));

    /* init request args */
    /*
    *  请求直接设计为GET方法，后续应该对其进行更改，协议种类为https
    */
    args->req_cfg.method = REQUEST_METHOD_POST;   
    strncpy(args->req_cfg.scheme, "https", sizeof(args->req_cfg.scheme));
    strncpy(args->req_cfg.url, "/", sizeof(args->req_cfg.url));
    strncpy(args->req_cfg.host, DEFAULT_HOST, sizeof(args->req_cfg.host));
}

int
xqc_mini_cli_init_ctx(xqc_mini_cli_ctx_t *ctx, xqc_mini_cli_args_t *args)
{
    memset(ctx, 0, sizeof(xqc_mini_cli_ctx_t));

    /* init event base */
    struct event_base *eb = event_base_new();
    ctx->eb = eb;

    ctx->args = args;

    /* init log writer fd */
    ctx->log_fd = xqc_mini_cli_open_log_file(ctx);
    if (ctx->log_fd < 0) {
        printf("[error] open log file failed\n");
        return XQC_ERROR;
    }
    /* init keylog writer fd */
    ctx->keylog_fd = xqc_mini_cli_open_keylog_file(ctx);
    if (ctx->keylog_fd < 0) {
        printf("[error] open keylog file failed\n");
        return XQC_ERROR;
    }

    return 0;
}


int
xqc_mini_cli_init_env(xqc_mini_cli_ctx_t *ctx, xqc_mini_cli_args_t *args)
{
    int ret = XQC_OK;

    /* init client args */
    xqc_mini_cli_init_args(args);
    
    /* init client ctx */
    ret = xqc_mini_cli_init_ctx(ctx, args);

    return ret;
}

xqc_scheduler_callback_t
xqc_mini_cli_get_sched_cb(xqc_mini_cli_args_t *args)
{
    xqc_scheduler_callback_t sched = xqc_minrtt_scheduler_cb;
    if (strncmp(args->quic_cfg.mp_sched, "minrtt", strlen("minrtt")) == 0) {
        sched = xqc_minrtt_scheduler_cb;

    } else if (strncmp(args->quic_cfg.mp_sched, "backup", strlen("backup")) == 0) {
        sched = xqc_backup_scheduler_cb;
    }
    else if (strncmp(args->quic_cfg.mp_sched, "balanced", strlen("balanced")) == 0) {
        sched = xqc_balanced_scheduler_cb;
    }
    else if (strncmp(args->quic_cfg.mp_sched, "rap", strlen("rap")) == 0) {
        sched = xqc_rap_scheduler_cb;
    }
    return sched;
}

xqc_cong_ctrl_callback_t
xqc_mini_cli_get_cc_cb(xqc_mini_cli_args_t *args)
{
    xqc_cong_ctrl_callback_t ccc = xqc_bbr_cb;
    switch (args->quic_cfg.cc) {
    case CC_TYPE_BBR:
        ccc = xqc_bbr_cb;
        break;
    case CC_TYPE_CUBIC:
        ccc = xqc_cubic_cb;
        break;
    default:
        break;
    }
    return ccc;
}

void
xqc_mini_cli_init_conn_settings(xqc_conn_settings_t *settings, xqc_mini_cli_args_t *args)
{
    /* parse congestion control callback */
    xqc_cong_ctrl_callback_t ccc = xqc_mini_cli_get_cc_cb(args);
    /* parse mp scheduler callback */
    xqc_scheduler_callback_t sched = xqc_mini_cli_get_sched_cb(args);

    /* init connection settings */
    memset(settings, 0, sizeof(xqc_conn_settings_t));
    settings->cong_ctrl_callback = ccc;
    settings->cc_params.customize_on = 1;
    settings->cc_params.init_cwnd = 96;
    settings->so_sndbuf = 1024*1024;
    settings->proto_version = XQC_VERSION_V1;
    settings->spurious_loss_detect_on = 1;
    settings->scheduler_callback = sched;
    settings->reinj_ctl_callback = xqc_deadline_reinj_ctl_cb;
    settings->adaptive_ack_frequency = 1;
    settings->enable_multipath = args->quic_cfg.multipath;
}

int
xqc_mini_cli_init_alpn_ctx(xqc_mini_cli_ctx_t *ctx)
{
    int ret = XQC_OK;

    /* init http3 callbacks */
    xqc_h3_callbacks_t h3_cbs = {
        .h3c_cbs = {
            .h3_conn_create_notify = xqc_mini_cli_h3_conn_create_notify,
            .h3_conn_close_notify = xqc_mini_cli_h3_conn_close_notify,
            .h3_conn_handshake_finished = xqc_mini_cli_h3_conn_handshake_finished,
        },
        .h3r_cbs = {
            .h3_request_create_notify = xqc_mini_cli_h3_request_create_notify,
            .h3_request_close_notify = xqc_mini_cli_h3_request_close_notify,
            .h3_request_read_notify = xqc_mini_cli_h3_request_read_notify,
            .h3_request_write_notify = xqc_mini_cli_h3_request_write_notify,
        }
    };

    /* init http3 context */
    ret = xqc_h3_ctx_init(ctx->engine, &h3_cbs);
    if (ret != XQC_OK) {
        printf("init h3 context error, ret: %d\n", ret);
        return ret;
    }

    return ret;
}

int
xqc_mini_cli_init_engine_ctx(xqc_mini_cli_ctx_t *ctx)
{
    int ret;

    /* init alpn ctx */
    ret = xqc_mini_cli_init_alpn_ctx(ctx);

    return ret;
}

void
xqc_mini_cli_free_ctx(xqc_mini_cli_ctx_t *ctx)
{
    xqc_mini_cli_close_keylog_file(ctx);
    xqc_mini_cli_close_log_file(ctx);
    
    if (ctx->args) {
        free(ctx->args);
        ctx->args = NULL;
    }
}

void
xqc_mini_cli_init_0rtt(xqc_mini_cli_args_t *args)
{
    /* read session ticket */
    int ret = xqc_mini_read_file_data(args->quic_cfg.session_ticket,
        SESSION_TICKET_BUF_MAX_SIZE, SESSION_TICKET_FILE);
    args->quic_cfg.session_ticket_len = ret > 0 ? ret : 0;

    /* read transport params */
    ret = xqc_mini_read_file_data(args->quic_cfg.transport_parameter,
        TRANSPORT_PARAMS_MAX_SIZE, TRANSPORT_PARAMS_FILE);
    args->quic_cfg.transport_parameter_len = ret > 0 ? ret : 0;

    /* read token */
    ret = xqc_mini_cli_read_token(
        args->quic_cfg.token, TOKEN_MAX_SIZE);
    args->quic_cfg.token_len = ret > 0 ? ret : 0;
}

void
xqc_mini_cli_init_conn_ssl_config(xqc_conn_ssl_config_t *conn_ssl_config, xqc_mini_cli_args_t *args)
{
    /* set session ticket and transport parameter args */
    if (args->quic_cfg.session_ticket_len < 0 || args->quic_cfg.transport_parameter_len < 0) {
        conn_ssl_config->session_ticket_data = NULL;
        conn_ssl_config->transport_parameter_data = NULL;

    } else {
        conn_ssl_config->session_ticket_data = args->quic_cfg.session_ticket;
        conn_ssl_config->session_ticket_len = args->quic_cfg.session_ticket_len;
        conn_ssl_config->transport_parameter_data = args->quic_cfg.transport_parameter;
        conn_ssl_config->transport_parameter_data_len = args->quic_cfg.transport_parameter_len;
    }
}

int
xqc_mini_cli_format_h3_req(xqc_http_header_t *headers, xqc_mini_cli_req_config_t* req_cfg,size_t body_len)
{
    /* response header buf list */
    
    static char content_length_buf[32];
    snprintf(content_length_buf, 32, "%zu", body_len);
    printf(">>>send_body_total_size:%s\n",content_length_buf);

    xqc_http_header_t req_hdr[] = {
        {
            .name = {.iov_base = ":method", .iov_len = 7},
            .value = {.iov_base = method_s[req_cfg->method], .iov_len = strlen(method_s[req_cfg->method])},
            .flags = 0,
        },
        {
            .name = {.iov_base = ":scheme", .iov_len = 7},
            .value = {.iov_base = req_cfg->scheme, .iov_len = strlen(req_cfg->scheme)},
            .flags = 0,
        },
        {
            .name   = {.iov_base = "host", .iov_len = 4},
            .value  = {.iov_base = req_cfg->host, .iov_len = strlen(req_cfg->host)},
            .flags  = 0,
        },
        {
            .name = {.iov_base = ":path", .iov_len = 5},
            .value = {.iov_base = req_cfg->url, .iov_len = strlen(req_cfg->path)},
            .flags = 0,
        },
        {
            .name   = {.iov_base = "content-type", .iov_len = 12},
            .value  = {.iov_base = "text/plain", .iov_len = 10},
            .flags  = 0,
        },
        {
            .name   = {.iov_base = "content-length", .iov_len = 14},
            .value  = {.iov_base = content_length_buf, .iov_len = strlen(content_length_buf)},
            .flags  = 0,
        },
    };

    size_t req_sz = sizeof(req_hdr) / sizeof(req_hdr[0]);
    if (req_sz > H3_HDR_CNT) {
        printf("[error] header length is too large, request_size: %zd\n", req_sz);
        return XQC_ERROR;
    }

    for (size_t i = 0; i < req_sz; i++) {
        headers[i] = req_hdr[i];
    }
    
    return req_sz;
}

int
xqc_mini_cli_request_send(xqc_h3_request_t *h3_request, xqc_mini_cli_user_stream_t *user_stream)
{
    

    // 发送 POST Body，最后一块要 fin = 1
    // ret = xqc_h3_request_send_body(h3_request,
    //                                (unsigned char *)body,
    //                                body_len,
    //                                1);
    // if (ret < 0) {
    //     printf("[error] send body failed: %d\n", ret);
    //     return -1;
    // }
    unsigned char *buffer = user_stream->send_buffer;
    xqc_mini_cli_ctx_t *ctx = user_stream->user_conn->ctx;
    if (!buffer) {
        perror("malloc");
        return -1;
    }
    while (user_stream->total_sent < user_stream->file_size
        || user_stream->buffered_sent < user_stream->buffered_len) {
        
         if (user_stream->buffered_sent == user_stream->buffered_len) {
            if (fseek(user_stream->send_body_fp, user_stream->total_sent, SEEK_SET) != 0) {
                perror("fseek");
                return -1;
            }
            user_stream->buffered_len = fread(buffer, 1, CHUNK_SIZE, user_stream->send_body_fp);
            user_stream->buffered_sent = 0;

            if (user_stream->buffered_len == 0) {
                if (feof(user_stream->send_body_fp)) {
                    if (user_stream->total_sent < user_stream->file_size) {
                        printf("[error] unexpected EOF after %zu/%zu bytes\n",
                               user_stream->total_sent, user_stream->file_size);
                        return -1;
                    }
                    break;
                }
                if (ferror(user_stream->send_body_fp)) {
                    perror("fread");
                    return -1;
                }
            }
        }
        
        size_t bytes_left_in_buffer = user_stream->buffered_len - user_stream->buffered_sent;
        int fin = (user_stream->total_sent + bytes_left_in_buffer >= user_stream->file_size) ? 1 : 0;

         ssize_t n = xqc_h3_request_send_body(h3_request,
            buffer + user_stream->buffered_sent, bytes_left_in_buffer, fin);
        if (n == -XQC_EAGAIN) {
            //ctx->args->net_cfg.last_socket_time = xqc_now();
            //printf("[info] send paused at start, waiting for write_notify\n");
            break;
        }
        if (n < 0) {
            printf("[error] send body failed: %zd\n", n);
            return -1;
        }
        user_stream->buffered_sent += n;
        user_stream->total_sent += n;

        printf(">>>already sent %ld bytes, remaining %ld bytes to send.\n",user_stream->total_sent, user_stream->file_size - user_stream->total_sent);
        ctx->args->net_cfg.last_socket_time = xqc_now();
        xqc_engine_main_logic(user_stream->user_conn->ctx->engine);

        if (user_stream->buffered_sent < user_stream->buffered_len) {
            continue;
        }

        if (fin) {
            printf("[info] total file sent: %zu bytes\n", user_stream->total_sent);
            break;
        }
    }

    return XQC_OK;
}

int
xqc_mini_cli_send_h3_req(xqc_mini_cli_user_conn_t *user_conn, xqc_mini_cli_user_stream_t *user_stream)
{
    user_stream->user_conn = user_conn;

    xqc_stream_settings_t settings = { .recv_rate_bytes_per_sec = 0 };
    user_stream->h3_request = xqc_h3_request_create(user_conn->ctx->engine, &user_conn->cid,
        &settings, user_stream);
    if (user_stream->h3_request == NULL) {
        printf("[error] xqc_h3_request_create error\n");
        return XQC_ERROR;
    }

    int ret, fin;
    /* send packet header/body */
    xqc_http_header_t header[H3_HDR_CNT];
    xqc_mini_cli_req_config_t* req_cfg;

    req_cfg = &user_stream->user_conn->ctx->args->req_cfg;
    // POST body
    // const char *body = "{\"name\":\"docker\",\"type\":\"client\"}";
    // size_t body_len = strlen(body);
    FILE *fp = fopen("client_sent.txt","rb");
    
    if(!fp ){
        perror("fopen");
        return -1;
    }

    user_stream->send_body_fp = fp;
    user_stream->total_sent =0;
    fseek(fp, 0, SEEK_END);
    size_t file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    user_stream->file_size = file_size;
    printf(">>>send_file_size:%ld",file_size);
    //fin = 1;
    ret = xqc_mini_cli_format_h3_req(header, req_cfg,file_size);
    if (ret > 0) {
        user_stream->h3_hdrs.headers = header;
        user_stream->h3_hdrs.count = ret;

        if (user_stream->start_time == 0) {
            user_stream->start_time = xqc_now();
        }
        /* send header */
        ret = xqc_h3_request_send_headers(user_stream->h3_request, &user_stream->h3_hdrs, 0);
        if (ret < 0) {
            printf("[error] xqc_mini_cli_h3_request_send error %d\n", ret);
            return -1;
        } else {
            printf("[stats] xqc_mini_cli_h3_request_send success \n");
            user_stream->hdr_sent = 1;
        }
    }
    if (req_cfg->method == REQUEST_METHOD_GET) {
        return XQC_OK;
    }
    user_stream->send_buffer = malloc(CHUNK_SIZE);
    user_stream->buffered_len = 0;
    user_stream->buffered_sent = 0;

    xqc_mini_cli_request_send(user_stream->h3_request, user_stream);

    /* generate engine main log to send packets */
    //xqc_engine_main_logic(user_conn->ctx->engine);
    return XQC_OK;
}

static const char *
xqc_mini_cli_get_interface_for_path(xqc_mini_cli_user_conn_t *user_conn, int path_index)
{
    xqc_mini_cli_net_config_t *net_cfg = &user_conn->ctx->args->net_cfg;
    if (path_index < 0 || path_index >= net_cfg->multi_interface_cnt) {
        return NULL;
    }

    if (net_cfg->multi_interface[path_index][0] == '\0') {
        return NULL;
    }

    return net_cfg->multi_interface[path_index];
}

static int
xqc_mini_cli_get_target_path_count(xqc_mini_cli_user_conn_t *user_conn)
{

    int target = user_conn->ctx->args->net_cfg.multi_interface_cnt;
    if (target <= 0) {
        return MAX_PATH_CNT;
    }

    if (target > MAX_PATH_CNT) {
        target = MAX_PATH_CNT;
    }
    if(target < 1) {
        target = 1;
    }
    return target;
}

static xqc_mini_cli_user_path_t *
xqc_mini_cli_find_inactive_path(xqc_mini_cli_user_conn_t *user_conn)
{
    for (int i = 0; i < MAX_PATH_CNT; i++) {
        if (!user_conn->paths[i].is_active) {
            return &user_conn->paths[i];
        }
    }

    return NULL;
}

static int
xqc_mini_cli_prepare_user_path(xqc_mini_cli_user_conn_t *user_conn, xqc_mini_cli_user_path_t *path)
{
    int ret;
    xqc_mini_cli_ctx_t *ctx = user_conn->ctx;
    int path_index = (int)(path - user_conn->paths);
    const char *interface_name = xqc_mini_cli_get_interface_for_path(user_conn, path_index);
    
    if (path->prepared) {
        return XQC_OK;
    }

    if (path->ev_socket) {
        event_del(path->ev_socket);
        event_free(path->ev_socket);
        path->ev_socket = NULL;
    }

    if (path->fd >= 0) {
        close(path->fd);
        path->fd = -1;
    }

    path->user_conn = user_conn;
    path->get_local_addr = 0;
    path->is_active = 0;
    path->prepared = 0;
    path->path_id = XQC_MINI_PATH_ID_INVALID;
    memset(path->interface_name, 0, sizeof(path->interface_name));
    if (interface_name != NULL) {
        strncpy(path->interface_name, interface_name, sizeof(path->interface_name) - 1);
    }

    if (path->local_addr == NULL) {
        path->local_addr = (struct sockaddr *)calloc(1, sizeof(struct sockaddr_in));
        if (path->local_addr == NULL) {
            return XQC_ERROR;
        }
    } else {
        memset(path->local_addr, 0, sizeof(struct sockaddr_in));
    }

    if (xqc_mini_cli_set_local_addr(path) != XQC_OK) {
        printf("[warn] set local address for path[%d] failed, fallback to wildcard\n", path_index);
    }
    if (path->peer_addr == NULL) {
        xqc_mini_cli_convert_text_to_sockaddr(AF_INET, DEFAULT_IP, DEFAULT_PORT,
            &(path->peer_addr), &(path->peer_addrlen));

        
    }
    
    ret = xqc_mini_cli_init_socket(path);
    if (ret != XQC_OK) {
        return ret;
    }

    path->ev_socket = event_new(ctx->eb, path->fd, EV_READ | EV_PERSIST,
        xqc_mini_cli_socket_event_callback, path);
    if (path->ev_socket == NULL) {
        close(path->fd);
        path->fd = -1;
        return XQC_ERROR;
    }

    path->prepared = 1;

    if (path->interface_name[0] != '\0') {
        printf("[stats] path[%d] prepared interface %s on fd %d (inactive)\n", path_index,
            path->interface_name, path->fd);
    } else {
        printf("[stats] path[%d] prepared on fd %d (inactive)\n", path_index, path->fd);
    }
    

    return XQC_OK;
}

static void
xqc_mini_cli_dump_path_bindings(xqc_mini_cli_user_conn_t *user_conn)
{
    int unique_fds[MAX_PATH_CNT];
    int unique_cnt = 0;

    for (int i = 0; i < MAX_PATH_CNT; i++) {
        unique_fds[i] = -1;
    }

    for (int i = 0; i < MAX_PATH_CNT; i++) {
        xqc_mini_cli_user_path_t *path = &user_conn->paths[i];
        if (!path->is_active || path->fd < 0) {
            continue;
        }

        const char *ifname = path->interface_name[0] != '\0' ?
            path->interface_name : "(default)";
        char local_buf[INET6_ADDRSTRLEN + 16] = {0};
        xqc_mini_cli_format_addr_port(path->local_addr, path->local_addrlen,
            local_buf, sizeof(local_buf));
        const char *local_str = local_buf[0] != '\0' ? local_buf : "-";
        printf("[stats] path[%d] fd=%d interface=%s local=%s\n", i, path->fd, ifname,
            local_str);

        int j;
        for (j = 0; j < unique_cnt; j++) {
            if (unique_fds[j] == path->fd) {
                printf("[warn] path[%d] shares fd %d with another active path\n", i, path->fd);
                break;
            }
        }

        if (j == unique_cnt && unique_cnt < MAX_PATH_CNT) {
            unique_fds[unique_cnt++] = path->fd;
        }
    }

    if (unique_cnt >= 2) {
        printf("[stats] detected %d distinct fds bound to interfaces above\n", unique_cnt);
    }
}

int
xqc_mini_cli_init_socket(xqc_mini_cli_user_path_t *user_path)
{
    int fd, size;
    xqc_mini_cli_ctx_t *ctx = user_path->user_conn->ctx;
    struct sockaddr *addr = user_path->local_addr;
    int path_index = (int)(user_path - user_path->user_conn->paths);
    const char *interface_name = xqc_mini_cli_get_interface_for_path(user_path->user_conn, path_index);

    fd = socket(addr->sa_family, SOCK_DGRAM, 0);
    if (fd < 0) {
        printf("[error] create socket failed, errno: %d\n", get_sys_errno());
        return XQC_ERROR;
    }
    if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE,
                   interface_name, strlen(interface_name)) < 0) {
        perror("SO_BINDTODEVICE");
    }
#ifdef XQC_SYS_WINDOWS
    if (ioctlsocket(fd, FIONBIO, &flags) == SOCKET_ERROR) {
		goto err;
	}
#else
    if (fcntl(fd, F_SETFL, O_NONBLOCK) == -1) {
        printf("[error] set socket nonblock failed, errno: %d\n", get_sys_errno());
        goto err;
    }
#endif

    size = 16 * 1024 * 1024;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(int)) < 0) {
        printf("[error] setsockopt failed, errno: %d\n", get_sys_errno());
        goto err;
    }

    if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &size, sizeof(int)) < 0) {
        printf("[error] setsockopt failed, errno: %d\n", get_sys_errno());
        goto err;
    }

#if !defined(__APPLE__)
    int val = IP_PMTUDISC_DO;
    setsockopt(fd, IPPROTO_IP, IP_MTU_DISCOVER, &val, sizeof(val));
#endif
    if (user_path->local_addrlen > 0) {
        if (bind(fd, (struct sockaddr *)user_path->local_addr, user_path->local_addrlen) < 0) {
            printf("[error] bind local address failed, errno: %d\n", get_sys_errno());
            goto err;
        }
    }
#if !defined(__APPLE__)
    if (connect(fd, (struct sockaddr *)user_path->peer_addr, user_path->peer_addrlen) < 0) {
        printf("[error] connect socket failed, errno: %d\n", get_sys_errno());
        goto err;
    }
#endif

    ctx->args->net_cfg.last_socket_time = xqc_now();
    printf("[stats] init socket succesfully \n");

    user_path->fd = fd;

    return XQC_OK;
err:
    close(fd);
    return XQC_ERROR;
}

void
xqc_mini_cli_socket_write_handler(xqc_mini_cli_user_path_t *user_path, int fd)
{
    DEBUG
    printf("[stats] socket write handler\n");
}

void
xqc_mini_cli_socket_read_handler(xqc_mini_cli_user_path_t *user_path, int fd)
{
    DEBUG
    ssize_t recv_size, recv_sum;
    uint64_t recv_time;
    xqc_int_t ret;
    unsigned char packet_buf[XQC_PACKET_BUF_LEN];
    xqc_mini_cli_ctx_t *ctx;
    xqc_mini_cli_user_conn_t *user_conn;

    recv_size = recv_sum = 0;
    user_conn = user_path->user_conn;
    ctx = user_conn->ctx;

    do {
        /* recv quic packet from server */
        recv_size = recvfrom(fd, packet_buf, sizeof(packet_buf), 0,
                             NULL, NULL);
        
        if (recv_size < 0 && get_sys_errno() == EAGAIN) {
            break;
        }

        if (recv_size < 0) {
            printf("recvfrom: recvmsg = %zd err=%s\n", recv_size, strerror(get_sys_errno()));
            break;
        }

        if (user_path->get_local_addr == 0) {
            user_path->get_local_addr = 1;
            user_path->local_addrlen = sizeof(struct sockaddr_storage);
            ret = getsockname(fd, (struct sockaddr*)user_path->local_addr,
                                        &user_path->local_addrlen);
            if (ret != 0) {
                printf("getsockname error, errno: %d\n", get_sys_errno());
                user_path->local_addrlen = 0;
                break;
            }
        }

        recv_sum += recv_size;
        recv_time = xqc_now();
        ctx->args->net_cfg.last_socket_time = recv_time;

        /* process quic packet with xquic engine */
        ret = xqc_engine_packet_process(ctx->engine, packet_buf, recv_size,
                                        user_path->local_addr, user_path->local_addrlen,
                                        user_path->peer_addr, user_path->peer_addrlen,
                                        (xqc_usec_t)recv_time, user_conn);
        if (ret != XQC_OK) {
            printf("[error] client_read_handler: packet process err, ret: %d\n", ret);
            return;
        }
    } while (recv_size > 0);

finish_recv:
    // printf("[stats] xqc_mini_cli_socket_read_handler, recv size:%zu\n", recv_sum);
    xqc_engine_finish_recv(ctx->engine);
}

static void
xqc_mini_cli_socket_event_callback(int fd, short what, void *arg)
{
    //DEBUG;
    xqc_mini_cli_user_path_t *user_path = (xqc_mini_cli_user_path_t *)arg;

    if (what & EV_WRITE) {
        xqc_mini_cli_socket_write_handler(user_path, fd);

    } else if (what & EV_READ) {
        xqc_mini_cli_socket_read_handler(user_path, fd);

    } else {
        printf("event callback: fd=%d, what=%d\n", fd, what);
        exit(1);
    }
}
int
xqc_mini_cli_init_xquic_connection(xqc_mini_cli_user_conn_t *user_conn)
{
    
    xqc_conn_ssl_config_t conn_ssl_config = {0};
    xqc_conn_settings_t conn_settings = {0};
    xqc_mini_cli_ctx_t *ctx;
    xqc_mini_cli_args_t *args;

    ctx = user_conn->ctx;
    args = ctx->args;

    /* load 0-rtt args */
    xqc_mini_cli_init_0rtt(ctx->args);

    /* init connection settings */
    xqc_mini_cli_init_conn_settings(&conn_settings, ctx->args);

    /* init connection ssl config */
    xqc_mini_cli_init_conn_ssl_config(&conn_ssl_config, ctx->args);

    xqc_mini_cli_user_path_t *path = &user_conn->paths[0];
    

    /* build connection */
    const xqc_cid_t *cid = xqc_h3_connect(ctx->engine, &conn_settings, args->quic_cfg.token,
        args->quic_cfg.token_len, args->req_cfg.host, args->quic_cfg.no_encryption, &conn_ssl_config,
        path->peer_addr, path->peer_addrlen, user_conn);
    if (cid == NULL) {
        return XQC_ERROR;
    }
    memcpy(&user_conn->cid, cid, sizeof(xqc_cid_t));
    printf("[stats] init xquic connection success \n");
    
    return XQC_OK;
}



static void
xqc_mini_cli_fill_wildcard_local_addr(struct sockaddr *local_addr, socklen_t *addrlen)
{
    struct sockaddr_in *addr_v4 = (struct sockaddr_in *)local_addr;
    memset(addr_v4, 0, sizeof(struct sockaddr_in));
    addr_v4->sin_family = AF_INET;
    addr_v4->sin_addr.s_addr = INADDR_ANY;
    addr_v4->sin_port = 0;
    *addrlen = sizeof(struct sockaddr_in);
}

static void
xqc_mini_cli_format_addr_port(const struct sockaddr *addr, socklen_t addrlen, char *buf, size_t buflen)
{
    if (buflen == 0) {
        return;
    }

    buf[0] = '\0';

    if (addr == NULL || addrlen == 0) {
        return;
    }

    char ip[INET6_ADDRSTRLEN] = {0};
    uint16_t port = 0;

    if (addr->sa_family == AF_INET) {
        const struct sockaddr_in *addr_v4 = (const struct sockaddr_in *)addr;
        if (inet_ntop(AF_INET, &addr_v4->sin_addr, ip, sizeof(ip)) == NULL) {
            return;
        }
        port = ntohs(addr_v4->sin_port);
        snprintf(buf, buflen, "%s:%u", ip, port);
        return;
    }

    if (addr->sa_family == AF_INET6) {
        const struct sockaddr_in6 *addr_v6 = (const struct sockaddr_in6 *)addr;
        if (inet_ntop(AF_INET6, &addr_v6->sin6_addr, ip, sizeof(ip)) == NULL) {
            return;
        }
        port = ntohs(addr_v6->sin6_port);
        snprintf(buf, buflen, "[%s]:%u", ip, port);
        return;
    }

    snprintf(buf, buflen, "af%d", addr->sa_family);
}

static int
xqc_mini_cli_query_interface_addr(const char *interface_name, int desired_family,
    struct sockaddr_storage *storage, socklen_t *addrlen)
{
#if defined(XQC_SYS_WINDOWS)
    (void)interface_name;
    (void)storage;
    (void)addrlen;
    return XQC_ERROR;
#else
    struct ifaddrs *ifaddr = NULL;
    if (getifaddrs(&ifaddr) != 0) {
        printf("[error] getifaddrs failed for %s: %d\n", interface_name, errno);
        return XQC_ERROR;
    }

    int ret = XQC_ERROR;
    struct ifaddrs *ifa = NULL;
    struct sockaddr_storage v6_candidate = {0};
    socklen_t v6_len = 0;
    int have_v6 = 0;

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_name == NULL || ifa->ifa_addr == NULL) {
            continue;
        }
        if (strcmp(ifa->ifa_name, interface_name) != 0) {
            continue;
        }

        if (desired_family == AF_UNSPEC || ifa->ifa_addr->sa_family == desired_family) {
            if (ifa->ifa_addr->sa_family == AF_INET) {
                memcpy(storage, ifa->ifa_addr, sizeof(struct sockaddr_in));
                struct sockaddr_in *addr_v4 = (struct sockaddr_in *)storage;
                addr_v4->sin_port = 0;
                *addrlen = sizeof(struct sockaddr_in);
                ret = XQC_OK;
                break;
            }

            if (ifa->ifa_addr->sa_family == AF_INET6) {
                memcpy(storage, ifa->ifa_addr, sizeof(struct sockaddr_in6));
                struct sockaddr_in6 *addr_v6 = (struct sockaddr_in6 *)storage;
                addr_v6->sin6_port = 0;
                *addrlen = sizeof(struct sockaddr_in6);
                ret = XQC_OK;
                break;
            }
        }

        if (desired_family == AF_UNSPEC && ifa->ifa_addr->sa_family == AF_INET6) {
            memcpy(&v6_candidate, ifa->ifa_addr, sizeof(struct sockaddr_in6));
            struct sockaddr_in6 *addr_v6 = (struct sockaddr_in6 *)&v6_candidate;
            addr_v6->sin6_port = 0;
            v6_len = sizeof(struct sockaddr_in6);
            have_v6 = 1;
        }
    }

    if (ret != XQC_OK && desired_family == AF_UNSPEC && have_v6) {
        memcpy(storage, &v6_candidate, v6_len);
        *addrlen = v6_len;
        ret = XQC_OK;
    }

    freeifaddrs(ifaddr);
    return ret;
#endif
}

static int
xqc_mini_cli_set_local_addr(xqc_mini_cli_user_path_t *path)
{
    socklen_t addrlen = 0;
    int ret = XQC_OK;
    if (path->interface_name[0] != '\0') {
        struct sockaddr_storage storage = {0};
        int desired_family = AF_UNSPEC;
        if (path->peer_addr != NULL) {
            desired_family = path->peer_addr->sa_family;
        } else {
            desired_family = AF_INET;
        }

        ret = xqc_mini_cli_query_interface_addr(path->interface_name, desired_family,
            &storage, &addrlen);
        if (ret == XQC_OK) {
            memcpy(path->local_addr, &storage, addrlen);
            path->local_addrlen = addrlen;
            return XQC_OK;
        }

        printf("[warn] query interface %s address failed\n", path->interface_name);
    } else {
        ret = XQC_OK;
    }

    xqc_mini_cli_fill_wildcard_local_addr(path->local_addr, &addrlen);
    path->local_addrlen = addrlen;
    return ret;
}

static int
xqc_mini_cli_init_user_path(xqc_mini_cli_user_conn_t *user_conn, xqc_mini_cli_user_path_t *path,
    uint64_t path_id)
{
    int path_index = (int)(path - user_conn->paths);
    
    int ret = xqc_mini_cli_prepare_user_path(user_conn, path);
    
    if (ret != XQC_OK) {
        return ret;
    }

    path->get_local_addr = 0;

    if (event_add(path->ev_socket, NULL) != 0) {
        printf("[error] event_add failed for path[%d]\n", path_index);
        event_free(path->ev_socket);
        path->ev_socket = NULL;
        if (path->fd >= 0) {
            close(path->fd);
            path->fd = -1;
        }
        path->prepared = 0;
        return XQC_ERROR;
    }

    path->path_id = path_id;
    path->is_active = 1;

    if (path->interface_name[0] != '\0') {
        printf("[stats] path[%d] interface %s bound fd %d\n", path_index,
            path->interface_name, path->fd);
    } else {
        printf("[stats] path[%d] bound fd %d\n", path_index, path->fd);
    }

    xqc_mini_cli_dump_path_bindings(user_conn);

    return XQC_OK;
}


static void
xqc_mini_cli_conn_ready_to_create_path(const xqc_cid_t *cid, void *conn_user_data)
{
    xqc_mini_cli_user_conn_t *user_conn = (xqc_mini_cli_user_conn_t *)conn_user_data;
    if (user_conn == NULL || user_conn->ctx == NULL) {
        return;
    }

    if (!user_conn->ctx->args->quic_cfg.multipath) {
        return;
    }

    int target_cnt = xqc_mini_cli_get_target_path_count(user_conn);
    if (user_conn->total_path_cnt >= target_cnt) {
        printf("[warn] reach max path count, ignore new path creation\n");
        return;
    }

    xqc_mini_cli_user_path_t *path = xqc_mini_cli_find_inactive_path(user_conn);
    if (path == NULL) {
        printf("[warn] no inactive path slot available for new path\n");
        return;
    }

    uint64_t new_path_id = 0;
    int ret = xqc_conn_create_path(user_conn->ctx->engine, cid, &new_path_id, 0);
    if (ret != XQC_OK) {
        printf("[error] xqc_conn_create_path error:%d\n", ret);
        return;
    }
    if (!path->prepared) {
        ret = xqc_mini_cli_prepare_user_path(user_conn, path);
        if (ret != XQC_OK) {
            printf("[error] prepare new path socket failed, ret:%d\n", ret);
            xqc_conn_close_path(user_conn->ctx->engine, cid, new_path_id);
            return;
        }
    }

    ret = xqc_mini_cli_init_user_path(user_conn, path, new_path_id);
    if (ret != XQC_OK) {
        printf("[error] init new path failed, ret:%d\n", ret);
        xqc_conn_close_path(user_conn->ctx->engine, cid, new_path_id);
        return;
    }

    user_conn->total_path_cnt++;
    user_conn->active_path_cnt++;
    printf("[stats] new path created, path_id=%"PRIu64"\n", new_path_id);
}

static void
xqc_mini_cli_path_removed(const xqc_cid_t *cid, uint64_t path_id, void *conn_user_data)
{
    xqc_mini_cli_user_conn_t *user_conn = (xqc_mini_cli_user_conn_t *)conn_user_data;
    if (user_conn == NULL) {
        return;
    }

    for (int i = 0; i < MAX_PATH_CNT; i++) {
        xqc_mini_cli_user_path_t *path = &user_conn->paths[i];
        if (path->is_active && path->path_id == path_id) {
            path->is_active = 0;
            if (user_conn->active_path_cnt > 0) {
                user_conn->active_path_cnt--;
            }
            if (user_conn->total_path_cnt > 0) {
                user_conn->total_path_cnt--;
            }
            if (path->ev_socket) {
                event_del(path->ev_socket);
                event_free(path->ev_socket);
                path->ev_socket = NULL;
            }
            if (path->fd >= 0) {
                close(path->fd);
                path->fd = -1;
            }
            path->prepared = 0;
            path->path_id = XQC_MINI_PATH_ID_INVALID;
            printf("[stats] path removed, path_id=%"PRIu64"\n", path_id);
            xqc_mini_cli_dump_path_bindings(user_conn);
            break;
        }
    }
}
int
xqc_mini_cli_main_process(xqc_mini_cli_user_conn_t *user_conn, xqc_mini_cli_ctx_t *ctx)
{
    int ret;
    xqc_mini_cli_args_t *args;

    user_conn->ctx = ctx;
    args = ctx->args;

    ret = xqc_mini_cli_init_xquic_connection(user_conn);
    if (ret < 0) {
        printf("[error] mini socket init xquic connection failed\n");
        return XQC_ERROR;
    }

    xqc_mini_cli_user_stream_t *user_stream = calloc(1, sizeof(xqc_mini_cli_user_stream_t));
    ret = xqc_mini_cli_send_h3_req(user_conn, user_stream);
    if (ret < 0) {
        return XQC_ERROR;
    }

    return XQC_OK;
}


xqc_mini_cli_user_conn_t *
xqc_mini_cli_user_conn_create(xqc_mini_cli_ctx_t *ctx)
{
    int ret;
    xqc_mini_cli_user_conn_t *user_conn = calloc(1, sizeof(xqc_mini_cli_user_conn_t));

    user_conn->ctx = ctx;
    for (int i = 0; i < MAX_PATH_CNT; i++) {
        user_conn->paths[i].fd = -1;
        user_conn->paths[i].user_conn = user_conn;
        user_conn->paths[i].is_active = 0;
        user_conn->paths[i].prepared = 0;
        user_conn->paths[i].path_id = XQC_MINI_PATH_ID_INVALID;
    }
    /* set connection timeout */
    struct timeval tv;
    tv.tv_sec = ctx->args->net_cfg.conn_timeout;
    tv.tv_usec = 0;
    user_conn->ev_timeout = event_new(ctx->eb, -1, 0, xqc_mini_cli_timeout_callback, user_conn);
    event_add(user_conn->ev_timeout, &tv);

    
    xqc_mini_cli_user_path_t *path0 = &user_conn->paths[0];
    
    ret = xqc_mini_cli_init_user_path(user_conn, path0, 0);
    // printf("path_id: %"PRIu64", address_path: %s,peer_address:%s\n",
    //            path0->path_id,inet_ntoa(((struct sockaddr_in*)path0->local_addr)->sin_addr),inet_ntoa(((struct sockaddr_in*)path0->peer_addr)->sin_addr));
    if (ret < 0) {
        printf("[error] mini socket init socket failed\n");
        xqc_mini_cli_free_user_conn(user_conn);
        return NULL;
    }

    user_conn->total_path_cnt = 1;
    user_conn->active_path_cnt = 1;

    int target_prepare = xqc_mini_cli_get_target_path_count(user_conn);
    for (int i = 1; i < target_prepare; i++) {
        xqc_mini_cli_user_path_t *path = &user_conn->paths[i];
        ret = xqc_mini_cli_prepare_user_path(user_conn, path);
        if (ret != XQC_OK) {
            printf("[warn] pre-bind for path[%d] failed, ret:%d\n", i, ret);
        }
    }


    return user_conn;
}

void
xqc_mini_cli_free_user_conn(xqc_mini_cli_user_conn_t *user_conn)
{
    if (user_conn == NULL) {
        return;
    }
    for (int i = 0; i < MAX_PATH_CNT; i++) {
        xqc_mini_cli_user_path_t *path = &user_conn->paths[i];
        if (path->ev_socket) {
            event_del(path->ev_socket);
            event_free(path->ev_socket);
            path->ev_socket = NULL;
        }
        if (path->fd >= 0) {
            close(path->fd);
            path->fd = -1;
        }
        free(path->peer_addr);
        free(path->local_addr);
        path->peer_addr = NULL;
        path->local_addr = NULL;
        path->prepared = 0;
        path->is_active = 0;
        path->path_id = XQC_MINI_PATH_ID_INVALID;
    }
    if (user_conn->ev_timeout) {
        event_del(user_conn->ev_timeout);
        event_free(user_conn->ev_timeout);
        user_conn->ev_timeout = NULL;
    }
    free(user_conn);
}

void
xqc_mini_cli_on_connection_finish(xqc_mini_cli_user_conn_t *user_conn)
{
     if (user_conn == NULL) {
        return;
    }
    if (user_conn->ev_timeout) {
        event_del(user_conn->ev_timeout);
        event_free(user_conn->ev_timeout);
        user_conn->ev_timeout = NULL;
    }

    for (int i = 0; i < MAX_PATH_CNT; i++) {
        xqc_mini_cli_user_path_t *path = &user_conn->paths[i];
        if (path->ev_socket) {
            event_del(path->ev_socket);
            event_free(path->ev_socket);
            path->ev_socket = NULL;
        }
        if (path->fd >= 0) {
            close(path->fd);
            path->fd = -1;
        }
    }
}

int main(int argc, char *argv[])
{
    int ret;
    xqc_mini_cli_ctx_t cli_ctx = {0}, *ctx = &cli_ctx;
    xqc_mini_cli_args_t *args = NULL;
    xqc_mini_cli_user_conn_t *user_conn = NULL;

    args = calloc(1, sizeof(xqc_mini_cli_args_t));
    if (args == NULL) {
        printf("[error] calloc args failed\n");
        goto exit;
    }

    /* init env (for windows) */
    xqc_platform_init_env();

    /* init client environment (ctx & args) */
    ret = xqc_mini_cli_init_env(ctx, args);
    if (ret < 0) {
        goto exit;
    }
    ret = xqc_mini_cli_parse_cmd_args(args, argc, argv);
    if (ret != XQC_OK) {
        goto exit;
    }
    /* init client engine */
    ret = xqc_mini_cli_init_xquic_engine(ctx, args);
    if (ret < 0) {
        printf("[error] init xquic engine failed\n");
        goto exit;
    }

    /* init engine ctx */
    ret = xqc_mini_cli_init_engine_ctx(ctx);
    if (ret < 0) {
        printf("[error] init engine ctx failed\n");
        goto exit;
    }

    user_conn = xqc_mini_cli_user_conn_create(ctx);
    if (user_conn == NULL) {
        printf("[error] init user_conn failed.\n");
        goto exit;
    }

    /* cli main process: build connection, process request, etc. */
    xqc_mini_cli_main_process(user_conn, ctx);

    /* start event loop */
    event_base_dispatch(ctx->eb);

exit:
    xqc_engine_destroy(ctx->engine);
    xqc_mini_cli_on_connection_finish(user_conn);
    xqc_mini_cli_free_ctx(ctx);
    xqc_mini_cli_free_user_conn(user_conn);

    return 0;
}
static int
xqc_mini_cli_parse_cmd_args(xqc_mini_cli_args_t *args, int argc, char *argv[])
{
    int opt;

    optind = 1;

    while ((opt = getopt(argc, argv, "i:")) != -1) {
        switch (opt) {
        case 'i':
            if (args->net_cfg.multi_interface_cnt >= MAX_PATH_CNT) {
                printf("[warn] exceed max path count %d, ignore interface %s\n",
                    MAX_PATH_CNT, optarg);
                break;
            }
            memset(args->net_cfg.multi_interface[args->net_cfg.multi_interface_cnt], 0,
                sizeof(args->net_cfg.multi_interface[args->net_cfg.multi_interface_cnt]));
            strncpy(args->net_cfg.multi_interface[args->net_cfg.multi_interface_cnt], optarg,
                XQC_MINI_INTERFACE_NAME_MAX_LEN - 1);
            printf("[stats] option interface[%d]=%s\n",
                args->net_cfg.multi_interface_cnt,
                args->net_cfg.multi_interface[args->net_cfg.multi_interface_cnt]);
            args->net_cfg.multi_interface_cnt++;
            break;
        default:
            break;
        }
    }

    return XQC_OK;
}

static int
xqc_mini_cli_bind_to_interface(int fd, const char *interface_name, int family)
{
#if !defined(XQC_SYS_WINDOWS)
#if !defined(__APPLE__)
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, interface_name, sizeof(ifr.ifr_name) - 1);
    printf("[stats] bind fd %d to interface %s\n", fd, interface_name);
    if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, (char *)&ifr, sizeof(ifr)) < 0) {
        printf("[error] bind to nic error: %d\n", errno);
        return XQC_ERROR;
    }
#else
    uint32_t if_index = if_nametoindex(interface_name);
    if (if_index == 0) {
        printf("[error] if_nametoindex failed for %s: %d\n", interface_name, errno);
        return XQC_ERROR;
    }

    printf("[stats] bind fd %d to interface %s (index %u)\n", fd, interface_name, if_index);

    int err = 0;
    if (family == AF_INET || family == AF_UNSPEC) {
        if (setsockopt(fd, IPPROTO_IP, IP_BOUND_IF, &if_index, sizeof(if_index)) == 0) {
            return XQC_OK;
        }
        err = errno;
        if (family == AF_INET) {
            printf("[error] bind to nic error: %d\n", err);
            return XQC_ERROR;
        }
    }

    if (family == AF_INET6 || family == AF_UNSPEC) {
        if (setsockopt(fd, IPPROTO_IPV6, IPV6_BOUND_IF, &if_index, sizeof(if_index)) == 0) {
            return XQC_OK;
        }
        err = errno;
        printf("[error] bind to nic error: %d\n", err);
        return XQC_ERROR;
    }

    printf("[error] unsupported address family %d for binding\n", family);
    return XQC_ERROR;
#endif
#else
    (void)fd;
    (void)interface_name;
    (void)family;
#endif
    return XQC_OK;
}