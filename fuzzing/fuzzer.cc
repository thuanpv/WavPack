#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "wavpack.h"

using namespace std;

#define BUF_SAMPLES 1024


extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    static int64_t times_called, successful_opens, samples_decoded;
    WavpackContext *wpc;
    char error [80];
    int num_chans;

    times_called++;

    if (!(times_called & 0x3FF))
        printf ("LLVMFuzzerTestOneInput() called %lld times, %lld successful opens, %lld samples decoded\n",
            (long long) times_called, (long long) successful_opens, (long long) samples_decoded);

    wpc = WavpackOpenMemoryFile ((void *) data, size, NULL, 0, error, OPEN_TAGS | OPEN_WRAPPER | OPEN_DSD_NATIVE | OPEN_ALT_TYPES, 0);

    if (!wpc)
        return 1;

    successful_opens++;
    num_chans = WavpackGetNumChannels (wpc);

    if (num_chans && num_chans <= 256) {
        int32_t decoded_samples [BUF_SAMPLES * num_chans];
        int unpack_result;

        do {
            unpack_result = WavpackUnpackSamples (wpc, decoded_samples, BUF_SAMPLES);
            samples_decoded += unpack_result;
        } while (unpack_result);
    }

    WavpackCloseFile (wpc);

    return 0;
}
