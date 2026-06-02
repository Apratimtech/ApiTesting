import { NextRequest, NextResponse } from "next/server";

/* =========================================================
   CONFIG
========================================================= */

const ALLOWED_METHODS = [
  "GET",
  "POST",
  "PUT",
  "PATCH",
  "DELETE",
  "HEAD",
  "OPTIONS",
];

const BLOCKED_HEADERS = [
  "host",
  "connection",
  "content-length",
  "transfer-encoding",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailers",
  "upgrade",
  "x-proxy-url",

  // IMPORTANT
  "accept-encoding",
  "content-encoding",
];

/* =========================================================
   METHODS
========================================================= */

export async function GET(req: NextRequest) {
  return handleProxy(req);
}

export async function POST(req: NextRequest) {
  return handleProxy(req);
}

export async function PUT(req: NextRequest) {
  return handleProxy(req);
}

export async function PATCH(req: NextRequest) {
  return handleProxy(req);
}

export async function DELETE(req: NextRequest) {
  return handleProxy(req);
}

export async function HEAD(req: NextRequest) {
  return handleProxy(req);
}

export async function OPTIONS() {
  return NextResponse.json(
    { success: true },
    {
      status: 200,
      headers: corsHeaders(),
    }
  );
}

/* =========================================================
   MAIN HANDLER
========================================================= */

async function handleProxy(
  req: NextRequest
): Promise<NextResponse> {

  const startTime = Date.now();

  try {

    /* =====================================================
       TARGET URL
    ===================================================== */

    const targetUrl =
      req.headers.get("x-proxy-url");

    if (!targetUrl) {

      return jsonError(
        "Missing x-proxy-url header",
        400
      );
    }

    /* =====================================================
       URL VALIDATION
    ===================================================== */

    let parsedUrl: URL;

    try {

      parsedUrl =
        new URL(targetUrl);

    } catch {

      return jsonError(
        "Invalid target URL",
        400
      );
    }

    if (
      !["http:", "https:"].includes(
        parsedUrl.protocol
      )
    ) {

      return jsonError(
        "Only HTTP/HTTPS protocols allowed",
        400
      );
    }

    /* =====================================================
       METHOD VALIDATION
    ===================================================== */

    if (
      !ALLOWED_METHODS.includes(
        req.method
      )
    ) {

      return jsonError(
        `Method ${req.method} not allowed`,
        405
      );
    }

    /* =====================================================
       FORWARD HEADERS
    ===================================================== */

    const forwardHeaders =
      new Headers();

    req.headers.forEach(
      (value, key) => {

        const lowerKey =
          key.toLowerCase();

        if (
          !BLOCKED_HEADERS.includes(
            lowerKey
          )
        ) {

          try {

            forwardHeaders.set(
              key,
              value
            );

          } catch (err) {

            console.error(
              "[HEADER_ERROR]",
              key,
              err
            );
          }
        }
      }
    );

    /* =====================================================
       BODY
    ===================================================== */

    let body:
      | string
      | undefined;

    const noBodyMethods = [
      "GET",
      "HEAD",
    ];

    if (
      !noBodyMethods.includes(
        req.method
      )
    ) {

      try {

        const rawBody =
          await req.text();

        if (
          rawBody &&
          rawBody.trim() !== "" &&
          rawBody !== "undefined" &&
          rawBody !== "null"
        ) {

          body = rawBody;
        }

      } catch (err) {

        console.error(
          "[BODY_PARSE_ERROR]",
          err
        );

        return jsonError(
          "Failed to parse request body",
          400
        );
      }
    }

    /* =====================================================
       DEBUG LOGGING
    ===================================================== */

    console.log(
      "========== PROXY REQUEST =========="
    );

    console.log({
      url: parsedUrl.toString(),
      method: req.method,
      headers:
        Object.fromEntries(
          forwardHeaders.entries()
        ),
      body,
    });

    /* =====================================================
       TIMEOUT
    ===================================================== */

    const controller =
      new AbortController();

    const timeout =
      setTimeout(() => {

        controller.abort();

      }, 30000);

    /* =====================================================
       FETCH
    ===================================================== */

    let externalRes: Response;

    try {

      externalRes = await fetch(
        parsedUrl.toString(),
        {
          method: req.method,

          headers:
            forwardHeaders,

          body,

          redirect: "follow",

          signal:
            controller.signal,

          cache: "no-store",
        }
      );

    } catch (fetchError: any) {

      clearTimeout(timeout);

      console.error(
        "[FETCH_ERROR]",
        fetchError
      );

      if (
        fetchError?.name ===
        "AbortError"
      ) {

        return jsonError(
          "Upstream request timeout",
          504
        );
      }

      return jsonError(
        fetchError?.message ||
          "Proxy request failed",
        502
      );
    }

    clearTimeout(timeout);

    /* =====================================================
       DEBUG RESPONSE
    ===================================================== */

    console.log(
      "========== PROXY RESPONSE =========="
    );

    console.log({
      status:
        externalRes.status,

      statusText:
        externalRes.statusText,
    });

    /* =====================================================
       RESPONSE HEADERS
    ===================================================== */

    const responseHeaders =
      new Headers();

    externalRes.headers.forEach(
      (value, key) => {

        const lowerKey =
          key.toLowerCase();

        if (
          !BLOCKED_HEADERS.includes(
            lowerKey
          )
        ) {

          try {

            responseHeaders.set(
              key,
              value
            );

          } catch (err) {

            console.error(
              "[RESPONSE_HEADER_ERROR]",
              key,
              err
            );
          }
        }
      }
    );

    /* =====================================================
       SECURITY HEADERS
    ===================================================== */

    responseHeaders.set(
      "x-proxy-powered-by",
      "TrustEdge"
    );

    responseHeaders.set(
      "x-response-time",
      `${Date.now() - startTime}ms`
    );

    responseHeaders.set(
      "cache-control",
      "no-store"
    );

    /* =====================================================
       CORS
    ===================================================== */

    const cors =
      corsHeaders();

    Object.entries(cors).forEach(
      ([key, value]) => {

        responseHeaders.set(
          key,
          value
        );
      }
    );

    /* =====================================================
       RESPONSE BODY
    ===================================================== */

    let responseText = "";

    try {

      responseText =
        await externalRes.text();

    } catch (err) {

      console.error(
        "[RESPONSE_PARSE_ERROR]",
        err
      );

      responseText = "";
    }

    /* =====================================================
       FINAL RESPONSE
    ===================================================== */

    return new NextResponse(
      responseText,
      {
        status:
          externalRes.status,

        statusText:
          externalRes.statusText,

        headers:
          responseHeaders,
      }
    );

  } catch (err: any) {

    console.error(
      "[PROXY_ERROR]",
      err
    );

    return jsonError(
      err?.message ||
        "Internal proxy error",
      500
    );
  }
}

/* =========================================================
   HELPERS
========================================================= */

function jsonError(
  message: string,
  status: number
) {

  return NextResponse.json(
    {
      success: false,

      error: message,

      status,

      timestamp:
        new Date().toISOString(),
    },
    {
      status,

      headers:
        corsHeaders(),
    }
  );
}

function corsHeaders() {

  return {
    "Access-Control-Allow-Origin":
      "*",

    "Access-Control-Allow-Methods":
      "GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD",

    "Access-Control-Allow-Headers":
      "*",
  };
}