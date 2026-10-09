require("dotenv").config();

const express = require("express");
const cors = require("cors");
const crypto = require("node:crypto");
const path = require("node:path");
const { getCachedCheck, saveCheck } = require("./database");

const app = express();
const PORT = Number(process.env.PORT) || 3000;
const frontendDirectory = __dirname;

app.use(cors({
  origin: ["http://localhost:5500", "http://127.0.0.1:5500"]
}));
app.use(express.json());

function durationToMilliseconds(duration) {
  const seconds = Number.parseFloat(duration);

  if (!Number.isFinite(seconds) || seconds <= 0) {
    return 0;
  }

  return Math.min(seconds * 1000, 24 * 60 * 60 * 1000);
}

async function checkWithGoogle(url) {
  const apiKey = process.env.GOOGLE_SAFE_BROWSING_API_KEY;

if (!apiKey) {
  throw new Error("Set GOOGLE_SAFE_BROWSING_API_KEY in backend/.env for local use or in the Render environment settings after deployment.");
}

  const apiUrl = new URL("https://safebrowsing.googleapis.com/v5/urls:search");
  apiUrl.searchParams.set("key", apiKey);
  apiUrl.searchParams.append("urls", url.href);

  const response = await fetch(apiUrl, {
    headers: { Accept: "application/json" },
    signal: AbortSignal.timeout(10000)
  });

  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    console.error("Safe Browsing returned HTTP", response.status);
    throw new Error("The threat-checking service could not complete the check.");
  }

  const threats = Array.isArray(data.threats) ? data.threats : [];
  const threatTypes = [
    ...new Set(threats.flatMap((threat) => threat.threatTypes || []))
  ];

  const checkedAt = new Date();
  const cacheMilliseconds = durationToMilliseconds(data.cacheDuration);

  return {
    urlHash: crypto.createHash("sha256").update(url.href).digest("hex"),
    domain: url.hostname,
    verdict: threats.length > 0 ? "known_threat" : "no_known_threat",
    threatTypes,
    checkedAt: checkedAt.toISOString(),
    expiresAt: new Date(checkedAt.getTime() + cacheMilliseconds).toISOString()
  };
}

function makePageResult(check) {
  const threatFound = check.verdict === "known_threat";

  return {
    level: threatFound ? "high" : "caution",
    badge: threatFound ? "KNOWN THREAT" : "NO KNOWN THREAT MATCH",
    title: check.domain,
    summary: threatFound
      ? "This link matched a known threat entry."
      : "Google Safe Browsing returned no known threat match for this URL. That does not prove the site or job offer is safe or genuine.",
    reasons: threatFound
      ? [
          `Google Safe Browsing lists this URL as: ${check.threatTypes.join(", ") || "a threat"}.`
        ]
      : ["No known threat was listed for this URL in Google Safe Browsing."],
    nextStep: threatFound
      ? "Don’t open the link or enter information. Visit the organization’s official website directly."
      : "Open the employer official website yourself and check that the exact job is listed there before sharing information or money.",
    platformNotice: null,
    status: `Threat check performed at ${check.checkedAt}. VeriRadar did not verify website ownership or whether the site is currently online.`
  };
}

// Serve only the public frontend files. Do not expose the backend folder,
// environment files, or SQLite database through a broad static directory.
app.get(["/", "/index.html"], (req, res) => {
  res.sendFile(path.join(frontendDirectory, "index.html"));
});

app.get("/company-check.html", (req, res) => {
  res.sendFile(path.join(frontendDirectory, "company-check.html"));
});

app.get("/styles.css", (req, res) => {
  res.sendFile(path.join(frontendDirectory, "styles.css"));
});

app.get("/app.js", (req, res) => {
  res.sendFile(path.join(frontendDirectory, "app.js"));
});

app.post("/api/check", async (req, res) => {
  const submittedUrl = req.body.url;

  if (typeof submittedUrl !== "string" || submittedUrl.trim() === "") {
    return res.status(400).json({ error: "Please provide a website URL." });
  }

  if (submittedUrl.length > 2048) {
    return res.status(400).json({ error: "That URL is too long to check." });
  }

  let url;

  try {
    url = new URL(submittedUrl.trim());
  } catch {
    return res.status(400).json({ error: "That doesn’t look like a valid URL." });
  }

  if (!["http:", "https:"].includes(url.protocol)) {
    return res.status(400).json({ error: "Please provide an HTTP or HTTPS URL." });
  }

  if (url.username || url.password) {
    return res.status(400).json({ error: "URLs containing usernames or passwords can’t be checked." });
  }

  const urlHash = crypto.createHash("sha256").update(url.href).digest("hex");

  try {
    let check = getCachedCheck(urlHash);

    if (!check) {
      check = await checkWithGoogle(url);
      saveCheck(check);
    }

    res.json(makePageResult(check));
  } catch (error) {
    console.error(error.message);
    res.status(502).json({
      error: error.message || "VeriRadar could not complete the threat check."
    });
  }
});

app.post("/api/analyze-job", async (req, res) => {
  const company = typeof req.body.company === "string" ? req.body.company.trim().slice(0, 200) : "";
  const submittedUrl = typeof req.body.url === "string" ? req.body.url.trim() : "";
  const text = typeof req.body.text === "string" ? req.body.text.trim().slice(0, 20000) : "";

  if (!company && !submittedUrl && !text) {
    return res.status(400).json({ error: "Enter a company name, a job link, or paste the offer." });
  }

  const warningRules = [
    {
      pattern: /\b(registration fee|application fee|training fee|processing fee|pay to apply|payment to apply)\b/i,
      message: "The offer appears to ask for a fee to apply, register, or receive training."
    },
    {
      pattern: /\b(deposit|recharge|top.?up)\b.{0,50}\b(earn|task|job|withdraw|commission|unlock)\b/i,
      message: "It may ask you to deposit, recharge, or top up money to complete tasks or withdraw earnings."
    },
    {
      pattern: /\b(guaranteed|assured)\b.{0,35}\b(income|salary|earnings|profit)\b/i,
      message: "It promises guaranteed income. Check whether the pay and duties are realistic."
    },
    {
      pattern: /\b(no experience|no interview)\b.{0,60}\b(high salary|high income|earn)\b/i,
      message: "It combines little screening or experience requirements with unusually high pay."
    },
    {
      pattern: /\b(gift card|cryptocurrency|crypto|bitcoin)\b.{0,60}\b(pay|fee|deposit|send|transfer)\b/i,
      message: "It may request payment through cryptocurrency or gift cards, which is difficult to recover."
    },
    {
      pattern: /\b(urgent|immediately|today only|limited time)\b/i,
      message: "It uses urgency that may pressure you to act before checking the offer."
    },
    {
      pattern: /\b(bank password|one.time password|otp|verification code|account password)\b/i,
      message: "It may request a password, one-time code, or other sensitive account information."
    }
  ];

  const reasons = warningRules
    .filter((rule) => rule.pattern.test(text))
    .map((rule) => rule.message);

  let urlCheck = {
    status: "not_provided",
    message: "No job link was provided; the URL was not checked."
  };

  if (submittedUrl) {
    let url;

    try {
      url = new URL(submittedUrl);
    } catch {
      urlCheck = {
        status: "invalid",
        message: "The supplied link is not a valid URL, so it was not checked."
      };
    }

    if (url && !["http:", "https:"].includes(url.protocol)) {
      urlCheck = {
        status: "invalid",
        message: "Only HTTP or HTTPS links can be checked."
      };
      url = null;
    }

    if (url && (url.username || url.password)) {
      urlCheck = {
        status: "invalid",
        message: "Links containing usernames or passwords cannot be checked."
      };
      url = null;
    }

    if (url && submittedUrl.length > 2048) {
      urlCheck = {
        status: "invalid",
        message: "The supplied link is too long to check."
      };
      url = null;
    }

    if (url) {
      try {
        const urlHash = crypto.createHash("sha256").update(url.href).digest("hex");
        let check = getCachedCheck(urlHash);

        if (!check) {
          check = await checkWithGoogle(url);
          saveCheck(check);
        }

        if (check.verdict === "known_threat") {
          urlCheck = {
            status: "known_threat",
            domain: check.domain,
            threatTypes: check.threatTypes,
            message: "Google Safe Browsing matched this link to a known threat."
          };
        } else {
          urlCheck = {
            status: "no_known_threat",
            domain: check.domain,
            message: "Google Safe Browsing returned no known threat match. This does not prove the link is safe."
          };
        }
      } catch (error) {
        console.error("Job offer URL check failed:", error.message);
        urlCheck = {
          status: "unavailable",
          domain: url.hostname,
          message: "The live URL threat check could not complete. The offer text review is still available."
        };
      }
    }
  }

  const threatFound = urlCheck.status === "known_threat";
  let level = "unknown";
  let badge = text ? "NO CHECKLIST WARNINGS" : "OFFER TEXT NEEDED";
  let title = "No checklist warnings detected";
  let summary = "No phrases from VeriRadar checklist matched the pasted text. This is not confirmation that the company or offer is genuine.";
  let nextStep = "Find the company’s official website independently and verify the exact opening before sharing documents or money.";

  if (!text) {
    badge = "OFFER TEXT NEEDED";
    title = "Offer text needed for this review";
    summary = "No offer text was supplied, so job-message warning signs could not be reviewed. Any submitted link is checked separately below.";
    nextStep = "Paste the job description or offer message. Verify any opening through the company’s official website.";
  } else if (reasons.length >= 2) {
    level = "high";
    badge = "SEVERAL WARNING SIGNS";
    title = "Several job-offer warning signs";
    summary = "The pasted text contains multiple patterns commonly associated with job scams. This is a warning, not a confirmed finding.";
    nextStep = "Pause before replying. Don’t pay fees or send sensitive information. Verify the opening through the company’s official website.";
  } else if (reasons.length === 1) {
    level = "caution";
    badge = "REVIEW CAREFULLY";
    title = "Review this offer carefully";
    summary = "One potential warning sign was found in the pasted text. Verify the offer independently before responding.";
    nextStep = "Check the exact opening on the company’s official careers page before sharing information or money.";
  }

  if (threatFound) {
    level = "high";
    badge = "KNOWN THREAT";
    title = "The supplied link matched a known threat";
    summary = "Google Safe Browsing reported a known threat for this link. The job text is assessed separately.";
    nextStep = "Do not open the link or enter information. Visit the company’s official website by typing its address yourself.";
    reasons.unshift("Threat type reported: " + (urlCheck.threatTypes.join(", ") || "known threat") + ".");
  } else if (text && reasons.length === 0) {
    level = "unknown";
    badge = "NO CHECKLIST WARNINGS";
  }

  const companyNote = company
    ? "Company name supplied: " + company + ". Check the exact opening on the company official careers page; this does not confirm the offer belongs to that company."
    : urlCheck.domain
      ? "Website in the submitted link: " + urlCheck.domain + ". This identifies the link host, not necessarily the employer. The Google Safe Browsing result is shown below."
      : "Enter the employer name or a link to add company and website context.";

  res.json({
    level,
    badge,
    title: company && !threatFound ? company + " — " + title : title,
    summary,
    reasons: reasons.length ? reasons : [text ? "No warning phrases from VeriRadar starter checklist matched. Check the Google Safe Browsing result and confirm the exact opening on the employer official careers page." : "No offer text was provided, so job-message warning signs could not be reviewed."],
    companyNote,
    urlNote: urlCheck.message,
    nextStep
  });
});
app.listen(PORT, () => {
  console.log(`VeriRadar is running on port ${PORT}`);
});
