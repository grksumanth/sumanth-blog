export const onRequest: PagesFunction = async (context) => {
  const { request } = context;

  const corsHeaders = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Amz-Date, X-Amz-Security-Token",
    "Access-Control-Max-Age": "86400",
  };

  // Handle CORS preflight requests
  if (request.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: corsHeaders,
    });
  }

  // Only allow POST requests for verification
  if (request.method !== "POST") {
    return new Response(
      JSON.stringify({ error: "Method not allowed. Please use POST." }),
      {
        status: 405,
        headers: {
          ...corsHeaders,
          "Content-Type": "application/json",
        },
      }
    );
  }

  try {
    let bodyText = "";
    try {
      bodyText = await request.text();
    } catch (e) {
      return new Response(
        JSON.stringify({ error: "Failed to read request body." }),
        {
          status: 400,
          headers: {
            ...corsHeaders,
            "Content-Type": "application/json",
          },
        }
      );
    }

    if (!bodyText) {
      return new Response(
        JSON.stringify({ error: "Request body cannot be empty. Expecting JSON payload." }),
        {
          status: 400,
          headers: {
            ...corsHeaders,
            "Content-Type": "application/json",
          },
        }
      );
    }

    let payload: any;
    try {
      payload = JSON.parse(bodyText);
    } catch (e) {
      return new Response(
        JSON.stringify({ error: "Invalid JSON payload." }),
        {
          status: 400,
          headers: {
            ...corsHeaders,
            "Content-Type": "application/json",
          },
        }
      );
    }

    // Extract verification parameters with defaults
    const stsUrl = payload.url || "https://sts.amazonaws.com/";
    const method = (payload.method || "POST").toUpperCase();
    const headersInput = payload.headers || {};
    const bodyInput = payload.body || "Action=GetCallerIdentity&Version=2011-06-15";

    // Validate the STS URL to prevent Server-Side Request Forgery (SSRF)
    if (!isStsUrl(stsUrl)) {
      return new Response(
        JSON.stringify({ error: "Invalid STS URL. Only official AWS STS endpoints are allowed." }),
        {
          status: 400,
          headers: {
            ...corsHeaders,
            "Content-Type": "application/json",
          },
        }
      );
    }

    // Filter and construct headers to send to AWS STS.
    // Only forward headers related to the signature, authentication, and request metadata.
    const headersToSend = new Headers();
    for (const [key, value] of Object.entries(headersInput)) {
      const lowerKey = key.toLowerCase();
      if (
        lowerKey.startsWith("x-amz-") ||
        lowerKey === "authorization" ||
        lowerKey === "content-type" ||
        lowerKey === "accept"
      ) {
        const headerValue = Array.isArray(value) ? value[0] : value;
        if (typeof headerValue === "string") {
          headersToSend.set(key, headerValue);
        }
      }
    }

    // Forward the request to the official AWS STS endpoint
    const stsResponse = await fetch(stsUrl, {
      method: method,
      headers: headersToSend,
      body: method === "POST" ? bodyInput : undefined,
    });

    const responseText = await stsResponse.text();

    if (!stsResponse.ok) {
      return new Response(
        JSON.stringify({
          error: "AWS STS request verification failed.",
          statusCode: stsResponse.status,
          awsResponse: responseText,
        }),
        {
          status: stsResponse.status,
          headers: {
            ...corsHeaders,
            "Content-Type": "application/json",
          },
        }
      );
    }

    // Determine content type of the response from AWS STS
    const contentType = stsResponse.headers.get("content-type") || "";
    if (contentType.includes("application/json")) {
      try {
        const parsed = JSON.parse(responseText);
        const result = parsed.GetCallerIdentityResponse?.GetCallerIdentityResult || parsed;
        return new Response(
          JSON.stringify({
            Arn: result.Arn || result.arn,
            Account: result.Account || result.account,
            UserId: result.UserId || result.userId,
          }),
          {
            status: 200,
            headers: {
              ...corsHeaders,
              "Content-Type": "application/json",
            },
          }
        );
      } catch (err: any) {
        return new Response(
          JSON.stringify({ error: "Failed to parse AWS STS JSON response.", details: err.message, response: responseText }),
          {
            status: 500,
            headers: {
              ...corsHeaders,
              "Content-Type": "application/json",
            },
          }
        );
      }
    } else {
      // Parse XML response using regex
      const arn = extractXmlTag(responseText, "Arn");
      const account = extractXmlTag(responseText, "Account");
      const userId = extractXmlTag(responseText, "UserId");

      if (!arn && !account && !userId) {
        return new Response(
          JSON.stringify({ error: "Could not parse AWS STS XML response.", response: responseText }),
          {
            status: 500,
            headers: {
              ...corsHeaders,
              "Content-Type": "application/json",
            },
          }
        );
      }

      return new Response(
        JSON.stringify({ Arn: arn, Account: account, UserId: userId }),
        {
          status: 200,
          headers: {
            ...corsHeaders,
            "Content-Type": "application/json",
          },
        }
      );
    }
  } catch (error: any) {
    return new Response(
      JSON.stringify({ error: "Internal server error", details: error.message }),
      {
        status: 500,
        headers: {
          ...corsHeaders,
          "Content-Type": "application/json",
        },
      }
    );
  }
};

// Helper function to validate official AWS STS hostnames
function isStsUrl(urlStr: string): boolean {
  try {
    const parsed = new URL(urlStr);
    if (parsed.protocol !== "https:") return false;
    const host = parsed.hostname;
    // Match sts.amazonaws.com, sts.us-east-1.amazonaws.com, sts.cn-north-1.amazonaws.com.cn, etc.
    const hostRegex = /^sts\.(?:[a-z0-9-]+\.)*amazonaws\.com(?:\.cn)?$/;
    return host === "sts.amazonaws.com" || hostRegex.test(host);
  } catch {
    return false;
  }
}

// Helper function to extract tags from XML
function extractXmlTag(xml: string, tag: string): string {
  const match = xml.match(new RegExp(`<${tag}>([^<]+)</${tag}>`));
  return match ? match[1] : "";
}
