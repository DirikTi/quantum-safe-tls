#include <pthread.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>
#include "bootstrap.h"
#include "tls/tls_server/tls_server.h"

int main()
{
    if (chdir("./build/") != 0) {
        perror("chdir failed");
        return 1;
    }
    char cwd[1024];
    getcwd(cwd, sizeof(cwd));

    TLS_CTX *tls_ctx = bootstrap();

    run_server(tls_ctx);

    return 0;
}