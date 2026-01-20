#include "mini_client.h"
#include <inttypes.h>
#include <stdint.h>
#include <netdb.h>
#include <ctype.h>
#include <strings.h>
int init_args(xqc_mini_cli_args_t** args, xqc_mini_cli_ctx_t *ctx,int argc, char *argv[]){
    int ret;

    *args = calloc(1, sizeof(xqc_mini_cli_args_t));
    if (*args == NULL) {
        printf("[error] calloc args failed\n");
        return XQC_ERROR;
    }

    ret = xqc_mini_cli_init_env(ctx, *args);
    if (ret < 0) return XQC_ERROR;

    //ret = xqc_mini_cli_parse_cmd_args(*args, argc, argv);
    //if (ret != XQC_OK) return XQC_ERROR;

    ret = xqc_mini_cli_init_xquic_engine(ctx, *args);
    if (ret < 0) {
        printf("[error] init xquic engine failed\n");
        return XQC_ERROR;
    }

    ret = xqc_mini_cli_init_engine_ctx(ctx);
    if (ret < 0) {
        printf("[error] init engine ctx failed\n");
        return XQC_ERROR;
    }

    return XQC_OK;
}

int create_connection(xqc_mini_cli_user_conn_t** user_conn, xqc_mini_cli_ctx_t *ctx){
    int ret;
    *user_conn = xqc_mini_cli_user_conn_create(ctx);
    if (*user_conn == NULL) {
        printf("[error] init user_conn failed.\n");
        return XQC_ERROR;
    }

    (*user_conn)->ctx = ctx;

    ret = xqc_mini_cli_init_xquic_connection(*user_conn);
    if (ret < 0) {
        printf("[error] mini socket init xquic connection failed\n");
        return XQC_ERROR;
    }

    return XQC_OK;
}

int send_h3_req(xqc_mini_cli_user_conn_t* user_conn, xqc_mini_cli_ctx_t *ctx){
    int ret;
    int stream_total = user_conn->target_requests;
    
    printf("[stats] launch %d concurrent request streams\n", stream_total);
    
    

    for (int i = 0; i < stream_total; i++) {
        xqc_mini_cli_user_stream_t *user_stream = calloc(1, sizeof(xqc_mini_cli_user_stream_t));

        if (user_stream == NULL) {
            printf("[error] calloc user_stream failed for stream %d\n", i);
            return XQC_ERROR;
        }
        
        ret = xqc_mini_cli_send_h3_req(user_conn, user_stream, i);
        if (ret < 0) {
            free(user_stream);
            return XQC_ERROR;
        }
    }

    return XQC_OK;
}

void start_event(xqc_mini_cli_ctx_t *ctx){
    event_base_dispatch(ctx->eb);
}

void close_all(xqc_mini_cli_ctx_t *ctx,xqc_mini_cli_user_conn_t *user_conn){
    xqc_engine_destroy(ctx->engine);
    xqc_mini_cli_on_connection_finish(user_conn);
    xqc_mini_cli_free_ctx(ctx);
    xqc_mini_cli_free_user_conn(user_conn);
}
int main(int argc, char *argv[]){
    
    xqc_mini_cli_ctx_t cli_ctx = {0}, *ctx = &cli_ctx;
    xqc_mini_cli_args_t *args = NULL;
    if(init_args(&args, ctx, argc, argv) ==XQC_ERROR){
        goto exit;
    }

    xqc_mini_cli_user_conn_t *user_conn = NULL;
    if(create_connection(&user_conn, ctx) == XQC_ERROR){
        goto exit;
    }
    if (user_conn == NULL) {
        printf("[error] init user_conn failed.\n");
        goto exit;
    }
    send_h3_req(user_conn, ctx);

    start_event(ctx);
exit:
    close_all(ctx,user_conn);

    return 0;
}