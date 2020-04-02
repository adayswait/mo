#include "appweb.h"
#include "mpr.h"
#include <iostream>

static void testAction(HttpConn *conn)
{
    std::cout << "handling" << std::endl;
    HttpQueue *q;

    q = conn->writeq;
    /*
        Set the HTTP response status
     */
    httpSetStatus(conn, 200);

    /*
        Add desired headers. "Set" will overwrite, add will create if not
        already defined.
     */
    httpAddHeaderString(conn, "Content-Type", "text/html");
    httpSetHeaderString(conn, "Cache-Control", "no-cache");

    HttpRoute *route = conn->rx->route;
    cchar *url = (route->prefix && *route->prefix) ? route->prefix : "/";

    httpWrite(q, "<html><title>%s</title><body>\r\n", url);
    httpWrite(q, "<p>param: %s</p>\n", httpGetParam(conn, "param", "undefined"));
    httpWrite(q, "<p>method: %s</p>\n", conn->rx->method);
    httpWrite(q, "<p>client: %s:%d</p>\n", conn->ip, conn->port);
    httpWrite(q, "<p>pattern: %s</p>\n", route->prefix);
    httpWrite(q, "<p>startSegment: %s</p>\n", route->startSegment);
    httpWrite(q, "<p>startWith: %s</p>\n", route->startWith);
    httpWrite(q, "<p>optimizedPattern: %s</p>\n", route->optimizedPattern);
    httpWrite(q, "<p>prefix: %s</p>\n", route->prefix);
    httpWrite(q, "<p>tplate: %s</p>\n", route->tplate);
    httpWrite(q, "<p>targetRule: %s</p>\n", route->targetRule);
    httpWrite(q, "<p>target: %s</p>\n", route->target);
    httpWrite(q, "<p>documents: %s</p>\n", route->documents);
    httpWrite(q, "<p>home: %s</p>\n", route->home);
    httpWrite(q, "<p>envPrefix: %s</p>\n", route->envPrefix);
    httpWrite(q, "<p>mode: %s</p>\n", route->mode);
    httpWrite(q, "<p>database: %s</p>\n", route->database);
    httpWrite(q, "<p>responseFormat: %s</p>\n", route->responseFormat);
    httpWrite(q, "<p>clientConfig: %s</p>\n", route->clientConfig);
    httpWrite(q, "<p>defaultLanguage: %s</p>\n", route->defaultLanguage);
    httpWrite(q, "<p>cookie: %s</p>\n", route->cookie);
    httpWrite(q, "<p>corsOrigin: %s</p>\n", route->corsOrigin);
    httpWrite(q, "<p>corsHeaders: %s</p>\n", route->corsHeaders);
    httpWrite(q, "<p>corsMethods: %s</p>\n", route->corsMethods);
    httpWrite(q, "<p>webSocketsProtocol: %s</p>\n", route->webSocketsProtocol);
    httpWrite(q, "</body></html>\r\n");

    /*
        Call finalize output and close the request.
        Delay closing if you want to do asynchronous output and close later.
     */
    httpFinalize(conn);

#if 0
    /*
        Useful things to do in actions
     */
    httpRedirect(conn, 302, "/other-uri");
    httpError(conn, 409, "My message : %d", 5);
#endif
}

void testCookie(HttpConn *conn)
{
    cchar *testCookie = "testCookie";
    HttpRoute *route = conn->rx->route;
    cchar *url = (route->optimizedPattern && *route->optimizedPattern) ? route->optimizedPattern : "/";
    int flags = (route->flags & HTTP_ROUTE_VISIBLE_SESSION) ? 0 : HTTP_COOKIE_HTTP;
    cchar *recvedTestCookie = httpGetCookie(conn, testCookie);
    if (recvedTestCookie)
    {
        httpWrite(conn->writeq, "recv cookie : %s=%s\n", testCookie, recvedTestCookie);
    }
    else
    {
        cchar *_cookie = "this is a test cookie";
        httpWrite(conn->writeq, "no cookie recved, set cookie : %s=%s\n", testCookie, _cookie);
        httpSetCookie(conn, testCookie, _cookie, url, NULL, 0, flags);
    }

    httpSetStatus(conn, 200);
    httpAddHeaderString(conn, "Content-Type", "text/plain");
    httpFinalize(conn);
}
void testSession(HttpConn *conn)
{
    cchar *testSession = "testSession";

    HttpSession *session = httpGetSession(conn, 0);
    if (session)
    {
        cchar *recvedSession = (cchar *)(mprLookupKey(session->data, testSession));
        httpWrite(conn->writeq, "with session : %s=%s\n", testSession, recvedSession);
    }
    else
    {
        cchar *_session = "1234567890";
        httpWrite(conn->writeq, "without session, set session : %s=%s\n", testSession, _session);
        httpSetSessionVar(conn, testSession, _session);
    }

    httpSetStatus(conn, 200);
    httpAddHeaderString(conn, "Content-Type", "text/plain");
    httpFinalize(conn);
}
/*
    Create a simple stand-alone web server
 */
int main(int argc, char **argv)
{
    Mpr *mpr;
    int rc;

    rc = MPR_ERR_CANT_CREATE;
    if ((mpr = mprCreate(0, NULL, MPR_USER_EVENTS_THREAD)) == 0)
    {
        mprError("Cannot create runtime");
        return -1;
    }
    if (httpCreate(HTTP_CLIENT_SIDE | HTTP_SERVER_SIDE) == 0)
    {
        mprError("Cannot create the HTTP services");
        return -1;
    }
    mprStart();

    if (maParseConfig("mo.conf") < 0)
    {
        mprError("Cannot parse the config file %s", "mo.conf");
        return -1;
    }

    httpDefineAction("/v1/test_action", testAction);
    httpDefineAction("/v1/test_cookie", testCookie);
    httpDefineAction("/v1/test_session", testSession);

    if (httpStartEndpoints() < 0)
    {
        mprError("Cannot start the web server");
        return -1;
    }
    mprServiceEvents(-1, 0);
    mprDestroy();
    return 0;
}
