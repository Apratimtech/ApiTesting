"use client";
import { useState, useEffect } from "react";
import { motion } from "framer-motion";
// ... import all your UI components (Button, Tabs, etc.) same as before

type BodyType = "none" | "json" | "form-data" | "x-www-form-urlencoded";

export default function HttpScreen() {
  // All your states from previous page.tsx
  const [method, setMethod] = useState("GET");
  const [url, setUrl] = useState("https://httpbin.org/get");
  const [authType, setAuthType] = useState<"no-auth" | "bearer" | "basic" | "api-key" | "jwt">("bearer");
  const [bearer, setBearer] = useState("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.example.token");
  const [basicUser, setBasicUser] = useState("");
  const [basicPass, setBasicPass] = useState("");
  const [apiKey, setApiKey] = useState("");
  const [headers, setHeaders] = useState([{ key: "Content-Type", value: "application/json" }]);
  const [bodyType, setBodyType] = useState<BodyType>("json");
  const [body, setBody] = useState(`{\n  "username": "admin",\n  "password": "123456"\n}`);
  const [graphqlVariables, setGraphqlVariables] = useState(`{\n  "id": 1\n}`);

  const [apiResponse, setApiResponse] = useState<any>(null);
  const [securityResult, setSecurityResult] = useState<any>(null);
  const [loading, setLoading] = useState(false);

  // Load from Sidebar
  useEffect(() => {
    const saved = localStorage.getItem("last_selected_request");
    if (saved) {
      try {
        const req = JSON.parse(saved);
        if (["HTTP", "GraphQL", "AI"].includes(req.type)) {
          setMethod(req.method || "GET");
          setUrl(req.url || "https://httpbin.org/get");
          if (req.authType) setAuthType(req.authType);
          if (req.bearer) setBearer(req.bearer);
          if (req.headers) setHeaders(req.headers);
          if (req.bodyType) setBodyType(req.bodyType);
          if (req.body) setBody(req.body);
        }
      } catch (e) {}
    }
  }, []);

  // ... Rest of your handleSend, saveCurrentRequest, UI code (same as the full page.tsx I gave earlier) ...

  return (
    // Paste your full beautiful UI here from the previous full page.tsx
    // Just change the title to show req.name if available
  );
}
