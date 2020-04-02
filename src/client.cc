#include "appweb.h"
#include "mpr.h"

int main(int argc, char **argv, char **envp)
{
    Http *http;
    HttpConn *conn;
    char *err;
    int status;

    /* 
       Create the Multithreaded Portable Runtime and start it.
     */
    mprCreate(argc, argv, 0);
    mprStart();

    /* 
       Get a client http object to work with. We can issue multiple requests with this one object.
       Add the conn as a root object so the GC won't collect it while we are using it.
     */
    http = httpCreate(HTTP_CLIENT_SIDE);

    /* 
        Open a connection to issue the GET. Then finalize the request output - this forces the request out.
     */
    if ((conn = httpRequest("GET", "http://127.0.1.1:8000/v1/test_action", NULL, 1, &err)) == 0)
    {
        mprError("Can't get URL: %s", err);
        exit(2);
    }
    status = httpGetStatus(conn);
    /* 
       Examine the HTTP response HTTP code. 200 is success.
     */
    if (status != 200)
    {
        mprError("Server responded with status %d\n", status);
        exit(1);
    }
    mprPrintf("Server responded with: %s\n", httpReadString(conn));
    mprDestroy();
    return 0;
}
