const scanForm = document.querySelector("#scan-form");
const urlInput = document.querySelector("#url-input");
const resultSection = document.querySelector("#result-section");
const riskBadge = document.querySelector("#risk-badge");
const resultTitle = document.querySelector("#result-title");
const resultSummary = document.querySelector("#result-summary");
const warningList = document.querySelector("#warning-list");
const saferStep = document.querySelector("#safer-step");
const checkStatus = document.querySelector("#check-status");
const platformNotice = document.querySelector("#platform-notice");
const platformNoticeTitle = document.querySelector("#platform-notice-title");
const platformNoticeCopy = document.querySelector("#platform-notice-copy");
const currentYear = document.querySelector("#current-year");
const API_BASE = location.port === "5500" ? "http://localhost:3000" : "";

const platformDirectory = [
  {
    domain: "theforage.com",
    name: "Forage",
    purpose: "Career exploration and virtual job simulations."
  },
  {
    domain: "google.com",
    name: "Google",
    purpose: "Search, email, maps, video, and other online tools."
  },
  {
    domain: "youtube.com",
    name: "YouTube",
    purpose: "Watching and sharing videos."
  },
  {
    domain: "linkedin.com",
    name: "LinkedIn",
    purpose: "Professional networking, jobs, and career information."
  },
  {
    domain: "paypal.com",
    name: "PayPal",
    purpose: "Online payments and money transfers."
  },
  {
    domain: "amazon.com",
    name: "Amazon",
    purpose: "Online shopping and other digital services."
  },
  {
    domain: "microsoft.com",
    name: "Microsoft",
    purpose: "Software, devices, and online services."
  },
  {
    domain: "apple.com",
    name: "Apple",
    purpose: "Apple products, software, and support."
  },
  {
    domain: "github.com",
    name: "GitHub",
    purpose: "Hosting and collaborating on software projects."
  }
];

const knownNames = platformDirectory.map(({ name }) => name.toLowerCase());

if (currentYear) {
  currentYear.textContent = new Date().getFullYear();
}

scanForm.addEventListener("submit", (event) => {
  event.preventDefault();

  let url;

  try {
    url = new URL(urlInput.value.trim());
  } catch {
    showResult({
      level: "high",
      badge: "CHECK THE ADDRESS",
      title: "Website not identified",
      summary: "What it is used for: VeriRadar couldn’t read this as a complete web address.",
      reasons: ["Enter a full address, such as https://example.com."],
      nextStep: "Check that you copied the whole link correctly.",
      platformNotice: {
        title: "Platform not identified",
        copy: "Enter a complete website address so VeriRadar can check its visible URL patterns."
      },
      status: "Check scope: address format only. No scam reports or website contents were checked."
    });
    return;
  }

  fetch(`${API_BASE}/api/check`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({ url: url.href })
  })
    .then(async (response) => {
      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || "The URL check failed.");
      }

      return data;
    })
    .then((data) => {
      showResult(data);
    })
    .catch((error) => {
      console.error(error);
      alert(error.message || "Could not connect to VeriRadar. If you are running locally, make sure the backend is running.");
    });
});

function findPlatform(hostname) {
  return platformDirectory.find(({ domain }) =>
    hostname === domain || hostname.endsWith(`.${domain}`)
  );
}

function checkAddress(url) {
  const hostname = url.hostname.toLowerCase();
  const platform = findPlatform(hostname);
  const warnings = [];
  const reasons = [];
  let riskScore = 0;

  if (url.protocol !== "https:") {
    warnings.push("This address does not use HTTPS.");
    riskScore += 2;
  } else {
    reasons.push(
      "The connection uses HTTPS. This protects information in transit, but does not prove who runs the site."
    );
  }

  if (hostname.includes("xn--")) {
    warnings.push("Encoded characters in this address could disguise a lookalike name.");
    riskScore += 3;
  }

  if (url.username || url.password) {
    warnings.push("This address contains login details before the website name, which can be misleading.");
    riskScore += 3;
  }

  const parts = hostname.split(".");
  const mainName = parts.length > 1 ? parts[parts.length - 2] : parts[0];

  if (parts.length >= 5) {
    warnings.push("This address has many sections, which can make the actual website name harder to spot.");
    riskScore += 1;
  }

  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) {
    warnings.push("This address uses a number instead of a familiar website name.");
    riskScore += 3;
  }

  const imitatesKnownName = knownNames.find((name) =>
    mainName.includes(name) &&
    mainName !== name &&
    !platform
  );

  if (imitatesKnownName) {
    warnings.push(`The website name contains “${imitatesKnownName}” but doesn’t match its listed domain.`);
    riskScore += 3;
  }

  if (platform) {
    reasons.unshift(
      `The address matches VeriRadar’s built-in domain entry for ${platform.name}. This identifies the domain; it does not guarantee every page or request is safe.`
    );
  }

  if (warnings.length > 0) {
    reasons.push(...warnings);
  } else {
    reasons.push("The basic address patterns checked by VeriRadar did not show an obvious warning sign.");
  }

  let level;
  let badge;
  let nextStep;

  if (riskScore >= 4) {
    level = "high";
    badge = "HIGH RISK SIGNS";
    nextStep =
      "Don’t enter a password or payment details. If the link claims to be from an organization, open its official app or website yourself.";
  } else if (riskScore > 0 || !platform) {
    level = "caution";
    badge = "USE CAUTION";
    nextStep = platform
      ? "Before signing in or paying, go to the organization’s official website yourself and compare the address."
      : "Look up the platform independently and compare the address before sharing personal or payment details.";
  } else {
    level = "low";
    badge = "LOW URL RISK SIGNS";
    nextStep =
      "The address matches VeriRadar’s built-in entry for this platform. Still pause if the link was unexpected or asks for money or sensitive information.";
  }

  const summary = platform
    ? `What it is used for: ${platform.purpose}`
    : "What it is used for: VeriRadar can’t confirm this platform’s purpose from the address alone.";

  const notice = platform
    ? null
    : {
        title: "Platform not identified",
        copy: `${hostname} isn’t in VeriRadar’s built-in platform list, so VeriRadar can’t confirm who runs it or what it is used for.`
      };

  return {
    level,
    badge,
    title: platform ? platform.name : hostname,
    summary,
    reasons,
    nextStep,
    platformNotice: notice,
    status:
      "Check scope: URL address patterns and VeriRadar’s built-in platform list only. No live scam reports or website contents were checked."
  };
}

function showResult(result) {
  riskBadge.textContent = result.badge;
  riskBadge.dataset.level = result.level;
  resultTitle.textContent = result.title;
  resultSummary.textContent = result.summary;
  saferStep.textContent = result.nextStep;
  checkStatus.textContent = result.status;

  warningList.replaceChildren();

  for (const reason of result.reasons) {
    const item = document.createElement("li");
    item.textContent = reason;
    warningList.append(item);
  }

  if (result.platformNotice) {
    platformNoticeTitle.textContent = result.platformNotice.title;
    platformNoticeCopy.textContent = result.platformNotice.copy;
    platformNotice.hidden = false;
  } else {
    platformNotice.hidden = true;
    platformNoticeTitle.textContent = "";
    platformNoticeCopy.textContent = "";
  }

  resultSection.hidden = false;
  resultSection.scrollIntoView({
    behavior: "smooth",
    block: "start"
  });
}
