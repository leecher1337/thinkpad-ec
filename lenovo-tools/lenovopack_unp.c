/*
 * Unpacker for Lenovo .exe firmware files
 *
 * (c) leecher@dose.0wnz.at 12/2025
 *
 * https://github.com/leecher1337/thinkpad-ec/tree/z585
 *
 * Compile with:    gcc -o lenovopack_unp lenovopack_unp.c -llzma
 *
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <lzma.h>
#include <fnmatch.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/types.h>
#ifndef FNM_CASEFOLD
#define FNM_CASEFOLD 0
#endif

typedef struct {
    char     name[256];
    uint32_t offset;      /* payload offset starting from header */
    uint32_t size;        /* size of payload */
    uint32_t flags;       /* 1 = LZMA-compressed, otherwise uncompressed */
    uint32_t padding;     /* unused */
} PACK_ENTRY;

/* read 32bit Little endian */
static uint32_t le32(const unsigned char *p)
{
    return  (uint32_t)p[0]        |
           ((uint32_t)p[1] << 8)  |
           ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

int main(int argc, char **argv)
{
    FILE *f;
    long file_size;
    long pos;
    unsigned char hdr[16];
    uint32_t header_size;
    uint32_t file_count;
    uint32_t entry_size;
    int do_extract;
    uint32_t i;
    char *targetdir = ".", destfile[PATH_MAX];

    entry_size = (uint32_t)sizeof(PACK_ENTRY);

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <bios.exe> [target directory] [file to extract]\n" \
        "If no file to extract is given, only contents will get listed\n" \
        "i.e.: %s bios.exe 60cn97ww.exe . \"*.CAP\"\n\n", argv[0], argv[0]);
        return 1;
    }

    if (do_extract = (argc >= 3))
    {
        targetdir = argv[2];
        mkdir(targetdir, 0777);
    }

    f = fopen(argv[1], "rb");
    if (f == NULL) {
        perror("fopen");
        return 1;
    }

    if (fseek(f, 0, SEEK_END) != 0) {
        perror("fseek");
        fclose(f);
        return 1;
    }
    file_size = ftell(f);
    if (file_size < 0) {
        perror("ftell");
        fclose(f);
        return 1;
    }

    /* Search "$PACK" signature */
    pos = file_size - 8;
    while (pos >= 0) {
        if (fseek(f, pos, SEEK_SET) != 0) {
            perror("fseek");
            fclose(f);
            return 1;
        }
        if (fread(hdr, 1, 8, f) != 8) {
            fprintf(stderr, "read error while searching\n");
            fclose(f);
            return 1;
        }
        if (memcmp(hdr, "$PACK", 5) == 0) {
            break;
        }
        pos--;
    }

    if (pos < 0) {
        fprintf(stderr, "No $PACK signature found\n");
        fclose(f);
        return 1;
    }

    /* Read header */
    if (fseek(f, pos, SEEK_SET) != 0) {
        perror("fseek");
        fclose(f);
        return 1;
    }
    if (fread(hdr, 1, 16, f) != 16) {
        fprintf(stderr, "Unable to read PACK header\n");
        fclose(f);
        return 1;
    }

    header_size = le32(hdr + 8);
    file_count  = le32(hdr + 12);

    if (file_count == 0) {
        fprintf(stderr, "file_count == 0, aborting\n");
        fclose(f);
        return 1;
    }

    if (fseek(f, 512, SEEK_CUR) != 0) {
        perror("fseek");
        fclose(f);
        return 1;
    }

    printf("$PACK at 0x%lX, header_size=0x%X, file_count=%u, entry_size=0x%X\n",
           pos, (unsigned int)header_size, (unsigned int)file_count,
           (unsigned int)entry_size);

    /* Read all entries */
    for (i = 0; i < file_count; i++) {
        FILE *out;
        PACK_ENTRY e;

        if (fread(&e, 1, sizeof(e), f) != sizeof(e)) {
            fprintf(stderr, "Error reading entry %u\n", i);
            fclose(f);
            return 1;
        }

        printf("%2u: %-20s  offset=0x%08X  size=0x%08X  flags=%u\n",
               (unsigned int)i, e.name,
               (unsigned int)e.offset, (unsigned int)e.size,
               (unsigned int)e.flags);

        if (do_extract && e.name[0] != '\0' && e.size > 0) {
            long offset;
            long left;
            long bytes;
            unsigned char buf[4096];

            if (argc >=4 && fnmatch(argv[3], e.name, FNM_CASEFOLD) != 0) continue;
            printf ("   -> Extracting...");
            fflush(stdout);

            offset = ftell(f);
            if (fseek(f, (long)e.offset, SEEK_SET) != 0) {
                perror("fseek data");
                fclose(f);
                return 1;
            }

            sprintf (destfile, "%s/%s", targetdir, e.name);
            out = fopen(destfile, "wb");
            if (out == NULL) {
                perror("fopen out");
                fclose(f);
                return 1;
            }

            if (e.flags == 1) {
                /* LZMA/XZ-compressed: decompress with liblzma */
                lzma_stream strm;
                lzma_ret ret;
                unsigned char inbuf[4096];
                unsigned char outbuf[4096];
                size_t r;
                uint64_t memlimit;
                int finished;

                memset(&strm, 0, sizeof(strm));
                memlimit = (uint64_t)(-1); /* no Limit */

                ret = lzma_auto_decoder(&strm, memlimit, 0);
                if (ret != LZMA_OK) {
                    fprintf(stderr, "lzma_auto_decoder failed for %s (ret=%d)\n",
                            e.name, (int)ret);
                    fclose(out);
                    fclose(f);
                    return 1;
                }

                finished = 0;
                left = (long)e.size;

                while (left > 0) {
                    bytes = (left >= (long)sizeof(inbuf)) ?
                            (long)sizeof(inbuf) : left;
                    r = fread(inbuf, 1, (size_t)bytes, f);
                    if (r != (size_t)bytes) {
                        fprintf(stderr,
                                "Error reading compressed data for %s\n",
                                e.name);
                        lzma_end(&strm);
                        fclose(out);
                        fclose(f);
                        return 1;
                    }
                    left -= bytes;

                    if (finished)
                        continue;

                    strm.next_in  = inbuf;
                    strm.avail_in = (size_t)bytes;

                    while (strm.avail_in > 0) {
                        size_t have;

                        strm.next_out  = outbuf;
                        strm.avail_out = sizeof(outbuf);

                        ret = lzma_code(&strm, LZMA_RUN);

                        if (ret != LZMA_OK && ret != LZMA_STREAM_END) {
                            fprintf(stderr,
                                    "lzma_code error (%d) for %s\n",
                                    (int)ret, e.name);
                            lzma_end(&strm);
                            fclose(out);
                            fclose(f);
                            return 1;
                        }

                        have = sizeof(outbuf) - strm.avail_out;
                        if (have > 0) {
                            if (fwrite(outbuf, 1, have, out) != have) {
                                fprintf(stderr, "Error writing %s\n", e.name);
                                lzma_end(&strm);
                                fclose(out);
                                fclose(f);
                                return 1;
                            }
                        }

                        if (ret == LZMA_STREAM_END) {
                            finished = 1;
                            break;
                        }
                    }
                }

                lzma_end(&strm);
            } else {
                /* copy uncompressed data */
                left = (long)e.size;
                while (left > 0) {
                    size_t r;
                    bytes = (left >= (long)sizeof(buf)) ?
                            (long)sizeof(buf) : left;
                    r = fread(buf, 1, (size_t)bytes, f);
                    if (r != (size_t)bytes) {
                        fprintf(stderr, "Error reading data for %s\n", e.name);
                        fclose(out);
                        fclose(f);
                        return 1;
                    }

                    if (fwrite(buf, 1, (size_t)bytes, out) != (size_t)bytes) {
                        fprintf(stderr, "Error writing %s\n", e.name);
                        fclose(out);
                        fclose(f);
                        return 1;
                    }
                    left -= bytes;
                }
            }

            fclose(out);
            printf ("OK\n");
            if (fseek(f, offset, SEEK_SET) != 0) {
                perror("fseek back");
                fclose(f);
                return 1;
            }
        }
    }

    fclose(f);
    return 0;
}
