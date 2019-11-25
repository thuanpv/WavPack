#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "wavpack.h"

using namespace std;

#define BUF_SAMPLES 1024


extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    WavpackContext *wpc;
    char error [80];
    int num_chans;

    wpc = WavpackOpenMemoryFile ((void *) data, size, NULL, 0, error, OPEN_TAGS | OPEN_WRAPPER | OPEN_DSD_NATIVE | OPEN_ALT_TYPES, 0);

    if (!wpc)
        return 1;

    num_chans = WavpackGetNumChannels (wpc);

    if (num_chans && num_chans <= 256) {
        int32_t decoded_samples [BUF_SAMPLES * num_chans];
        while (WavpackUnpackSamples (wpc, decoded_samples, BUF_SAMPLES));
    }

    WavpackCloseFile (wpc);

    return 0;
}
