#include <libmilter/mfapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

// Callback for end of headers
sfsistat mlfi_eoh(SMFICTX *ctx) {
    syslog(LOG_INFO, "MINIMAL_TEST: Adding header at EOH");
    
    if (smfi_addheader(ctx, "X-Minimal-Test", "Added-By-LibMilter") != MI_SUCCESS) {
        syslog(LOG_ERR, "MINIMAL_TEST: Failed to add header");
    } else {
        syslog(LOG_INFO, "MINIMAL_TEST: Header added successfully");
    }
    
    return SMFIS_CONTINUE;
}

// Milter callbacks structure
struct smfiDesc smfilter = {
    "minimal-test",     // filter name
    SMFI_VERSION,       // version code
    SMFIF_ADDHDRS,      // flags - we want to add headers
    NULL,               // connection callback
    NULL,               // HELO callback
    NULL,               // envelope sender callback
    NULL,               // envelope recipient callback
    NULL,               // header callback
    mlfi_eoh,           // end of headers callback
    NULL,               // body callback
    NULL,               // end of message callback
    NULL,               // abort callback
    NULL,               // close callback
    NULL,               // unknown command callback
    NULL,               // DATA callback
    NULL                // negotiate callback
};

int main(int argc, char **argv) {
    openlog("minimal-test-milter", LOG_PID, LOG_MAIL);
    
    // Set socket
    if (smfi_setconn("local:/var/run/minimal-test.sock") != MI_SUCCESS) {
        syslog(LOG_ERR, "smfi_setconn failed");
        return 1;
    }
    
    // Register milter
    if (smfi_register(smfilter) != MI_SUCCESS) {
        syslog(LOG_ERR, "smfi_register failed");
        return 1;
    }
    
    syslog(LOG_INFO, "Starting minimal test milter");
    
    // Start milter
    return smfi_main();
}
