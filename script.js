/* script.js: Real-Time Password Strength and Crack Time Analyzer
 *
 * Features:
 * - Shannon entropy estimation with charset pool detection
 * - Robust pattern penalties: repeats, sequential walks, keyboard paths, and low character diversity
 * - Multi-scenario cracking time estimation:
 *     1. Offline Fast Hash (100 billion guesses/sec via modern GPU clusters)
 *     2. Offline Hardened Slow Hash (10,000 guesses/sec via bcrypt/Argon2)
 *     3. Online Throttled Authentication (100 attempts/hour)
 * - Real-time accessibility announcements and checklist
 * - Client-side secure password generation
 * - 100% local execution with zero network transmission
 */

const passwordEl = document.getElementById("password");
const meterBar = document.getElementById("meterBar");
const strengthText = document.getElementById("strengthText");
const checksList = document.getElementById("checks");
const toggleVis = document.getElementById("toggleVis");
const generateBtn = document.getElementById("generate");
const copyBtn = document.getElementById("copyBtn");
const clearBtn = document.getElementById("clearBtn");

const crackBadge = document.getElementById("crackBadge");
const crackPrimaryTime = document.getElementById("crackPrimaryTime");
const crackPrimarySubtitle = document.getElementById("crackPrimarySubtitle");
const timeFastGpu = document.getElementById("timeFastGpu");
const timeSlowHash = document.getElementById("timeSlowHash");
const timeOnline = document.getElementById("timeOnline");

// Curated set of high-frequency breached passwords, dictionary stems, and default credentials
// Derived from SecLists, RockYou top 500, and annual breach intelligence reports
const COMMON = new Set([
  // Top numeric patterns
  "123456", "123456789", "12345678", "12345", "1234567", "1234", "1234567890",
  "000000", "111111", "222222", "333333", "444444", "555555", "666666", "777777",
  "888888", "999999", "112233", "121212", "654321", "123123", "123321", "1111", "0000",

  // Keyboard walks & layouts
  "qwerty", "qwertyuiop", "qwertz", "azerty", "asdfgh", "asdfghjkl", "zxcvbn", "zxcvbnm",
  "1qaz2wsx", "qazwsx", "wsxedc", "zaq12wsx",

  // IT defaults, systems & administrative credentials
  "admin", "administrator", "root", "toor", "guest", "user", "master", "manager",
  "operator", "default", "system", "server", "login", "welcome", "welcome1", "access",
  "passcode", "changeme", "changeit", "service", "support", "oracle", "cisco", "database",
  "test", "testing", "temp", "temporary", "public", "private", "security", "network",
  "gateway", "passwd", "password", "password1", "pass1234", "pass123",

  // Pop culture, superhero & entertainment
  "superman", "batman", "spiderman", "ironman", "pokemon", "pikachu", "starwars",
  "skywalker", "vader", "matrix", "gandalf", "harrypotter", "hulk", "avengers",
  "terminator", "wolverine", "optimus", "marvel", "disney", "metallica",

  // Seasons, months & calendar
  "summer", "winter", "spring", "autumn", "january", "february", "march", "april",
  "may", "june", "july", "august", "september", "october", "november", "december",
  "monday", "friday", "sunday", "holiday",

  // Sports & famous global clubs
  "football", "baseball", "basketball", "soccer", "hockey", "tennis", "golf",
  "chelsea", "arsenal", "liverpool", "barcelona", "realmadrid", "manchester",
  "lakers", "bulls", "cowboys", "patriots", "yankees", "redsox", "dodgers",

  // Common breached first names
  "michael", "jessica", "daniel", "thomas", "charlie", "jordan", "william", "andrew",
  "alexander", "robert", "david", "james", "john", "joseph", "anthony", "matthew",
  "ashley", "sarah", "emily", "amanda", "melissa", "nicole", "elizabeth", "stephanie",
  "jennifer", "richard", "charles", "george", "edward", "brian", "kevin", "donald",

  // Common English nouns, adjectives & passphrases
  "iloveyou", "iloveu", "loveyou", "monkey", "dragon", "shadow", "killer", "sunshine",
  "princess", "computer", "letmein", "trustno1", "trustme", "secret", "hunter2",
  "freedom", "whatever", "nothing", "forever", "monster", "champion", "warrior",
  "diamond", "millionaire", "bullet", "knight", "blessed", "cookie", "cheese",
  "coffee", "chocolate", "banana", "pepper", "orange", "apple", "peanut", "butter",
  "yellow", "black", "white", "green", "purple", "silver", "golden", "rainbow",
  "flower", "garden", "ocean", "river", "mountain", "thunder", "blizzard", "storm",
  "mustang", "ferrari", "porsche", "camaro", "corvette", "mercedes", "harley"
]);

passwordEl.addEventListener("input", onInput);
toggleVis.addEventListener("click", toggleVisibility);
generateBtn.addEventListener("click", generatePassword);
copyBtn.addEventListener("click", copyPassword);
clearBtn.addEventListener("click", clearPassword);

// Initial render
onInput();

function onInput() {
  const pw = passwordEl.value ? passwordEl.value.slice(0, 128) : "";
  const analysis = analyzePassword(pw);
  renderMeter(analysis);
  renderCrackTime(analysis, pw);
  renderChecks(pw, analysis);
}

function analyzePassword(rawPw) {
  const pw = rawPw ? rawPw.slice(0, 128) : "";
  const length = pw.length;
  if (length === 0) {
    return {
      length: 0,
      hasLower: false,
      hasUpper: false,
      hasDigit: false,
      hasSymbol: false,
      pool: 0,
      entropy: 0,
      adjustedEntropy: 0,
      repeats: 0,
      seqs: 0,
      keyboardSeqs: 0,
      uniqueChars: 0,
      diversityRatio: 0,
      pureSame: false,
      pureSequence: false,
      pureKeyboard: false,
      score: 0,
      suggestions: [],
      isCommon: false,
      crackTimes: calculateCrackTimes(0, false, 0)
    };
  }

  const hasLower = /[a-z]/.test(pw);
  const hasUpper = /[A-Z]/.test(pw);
  const hasDigit = /[0-9]/.test(pw);
  const hasSymbol = /[^A-Za-z0-9]/.test(pw);

  // Estimate character pool
  let pool = 0;
  if (hasLower) pool += 26;
  if (hasUpper) pool += 26;
  if (hasDigit) pool += 10;
  if (hasSymbol) pool += 33; // Common printable ASCII symbols

  // Shannon entropy approximation: length * log2(pool)
  let rawEntropy = length * Math.log2(Math.max(2, pool));

  // Check common password or dictionary stem
  const lowerPw = pw.toLowerCase();
  const stem = lowerPw.replace(/[0-9!@#$%^&*\-_+=.]*$/, "");
  const wrappedStem = lowerPw.replace(/^[0-9!@#$%^&*\-_+=.]+/, "").replace(/[0-9!@#$%^&*\-_+=.]+$/, "");
  const isCommon = COMMON.has(lowerPw) || 
    (stem.length >= 4 && COMMON.has(stem)) || 
    (wrappedStem.length >= 4 && COMMON.has(wrappedStem));

  // Pattern detection
  const repeats = countRepeatedSequences(pw);
  const seqs = countSequentialRuns(pw);
  const keyboardSeqs = countKeyboardSequences(pw);
  const pureSame = isAllSameChar(pw);
  const pureSequence = isPureSequence(pw);
  const pureKeyboard = isPureKeyboardWalk(pw);

  // Character diversity
  const uniqueChars = new Set(pw).size;
  const diversityRatio = uniqueChars / length;

  let adjustedEntropy = rawEntropy;

  if (isCommon) {
    adjustedEntropy = 0;
  } else if (pureSame) {
    // Single repeating character like "aaaaaaa"
    adjustedEntropy = Math.log2(pool);
  } else if (pureSequence || pureKeyboard) {
    // String is purely a sequence walk like "abcdefg" or "qwertyuiop"
    adjustedEntropy = Math.min(6, Math.log2(pool));
  } else {
    // Character diversity penalty
    let diversityPenalty = 0;
    if (diversityRatio < 0.4 && length > 4) {
      diversityPenalty = (1 - diversityRatio) * (rawEntropy * 0.4);
    }

    const patternPenalty = repeats * 1.5 + seqs * 2.2 + keyboardSeqs * 2.8 + diversityPenalty;
    adjustedEntropy = Math.max(0, rawEntropy - patternPenalty);
  }

  // Qualitative score from 0 to 5
  let score = 0;
  if (adjustedEntropy < 28) score = 0; // Very weak
  else if (adjustedEntropy < 36) score = 1; // Weak
  else if (adjustedEntropy < 60) score = 2; // Fair
  else if (adjustedEntropy < 80) score = 3; // Good
  else if (adjustedEntropy < 120) score = 4; // Very good
  else score = 5; // Excellent

  const crackTimes = calculateCrackTimes(adjustedEntropy, isCommon, length);
  const suggestions = generateActionableRecommendations(pw, {
    length,
    hasLower,
    hasUpper,
    hasDigit,
    hasSymbol,
    repeats,
    seqs,
    keyboardSeqs,
    uniqueChars,
    diversityRatio,
    pureSame,
    pureSequence,
    pureKeyboard,
    isCommon
  });

  return {
    length,
    hasLower,
    hasUpper,
    hasDigit,
    hasSymbol,
    pool,
    entropy: rawEntropy,
    adjustedEntropy,
    repeats,
    seqs,
    keyboardSeqs,
    uniqueChars,
    diversityRatio,
    pureSame,
    pureSequence,
    pureKeyboard,
    score,
    suggestions,
    isCommon,
    crackTimes
  };
}

/*
 * Accurate multi-scenario cracking time calculator
 * Scenarios:
 * 1. Offline Fast Hash: 100 billion guesses/sec (e.g. Hashcat on multi-GPU RTX 4090 cluster cracking MD5/SHA256)
 * 2. Offline Hardened Slow Hash: 10,000 guesses/sec (e.g. bcrypt cost 12 or Argon2id)
 * 3. Online Throttled: 100 attempts/hour (~0.0278 guesses/sec via defended login endpoint)
 */
function calculateCrackTimes(entropy, isCommon, length) {
  if (length === 0) {
    return {
      tier: "awaiting",
      badgeLabel: "Awaiting input",
      primaryTime: "-",
      formattedFastGpu: "-",
      formattedSlowHash: "-",
      formattedOnline: "-",
      subtitle: "Calculates time across modern GPUs, slow hashes, and online defenses"
    };
  }

  if (isCommon) {
    return {
      tier: "vulnerable",
      badgeLabel: "Vulnerable",
      primaryTime: "Instantly",
      formattedFastGpu: "Instantly (< 1 sec)",
      formattedSlowHash: "Instantly (< 1 sec)",
      formattedOnline: "Instantly (dictionary)",
      subtitle: "Found in common password wordlists: crackable in milliseconds by dictionary tools."
    };
  }

  if (entropy <= 1) {
    return {
      tier: "vulnerable",
      badgeLabel: "Vulnerable",
      primaryTime: "Instantly",
      formattedFastGpu: "Instantly (< 1 sec)",
      formattedSlowHash: "Instantly (< 1 sec)",
      formattedOnline: "Instantly (< 1 sec)",
      subtitle: "Minimal search space: crackable immediately on any device."
    };
  }

  const RATE_FAST_GPU = 1e11; // 100,000,000,000 guesses/sec
  const RATE_SLOW_HASH = 1e4; // 10,000 guesses/sec
  const RATE_ONLINE = 100 / 3600; // ~0.02778 guesses/sec (100 attempts / hour)
  const SECONDS_PER_YEAR = 31557600; // 365.25 days

  // Compute scenario durations using high-precision logarithmic calculations for large entropy
  function getScenario(rate) {
    if (entropy <= 100) {
      const averageGuesses = Math.pow(2, Math.max(0, entropy - 1));
      const secs = averageGuesses / rate;
      return {
        seconds: secs,
        formatted: formatSecondsDuration(secs)
      };
    } else {
      // log10(seconds) = (entropy - 1) * log10(2) - log10(rate)
      const log10Guesses = (entropy - 1) * 0.3010299956639812;
      const log10Secs = log10Guesses - Math.log10(rate);
      const log10Years = log10Secs - Math.log10(SECONDS_PER_YEAR);
      return {
        seconds: Infinity,
        formatted: formatLogYears(log10Years)
      };
    }
  }

  const fastScenario = getScenario(RATE_FAST_GPU);
  const slowScenario = getScenario(RATE_SLOW_HASH);
  const onlineScenario = getScenario(RATE_ONLINE);

  // Risk categorization based on the worst-case offline GPU attack
  let tier = "vulnerable";
  let badgeLabel = "Vulnerable";
  let subtitle = "Vulnerable: crackable almost instantly using consumer GPU hardware.";

  const fastSecs = fastScenario.seconds;
  if (!isFinite(fastSecs) || fastSecs >= SECONDS_PER_YEAR * 1000) {
    tier = "future-proof";
    badgeLabel = "Future-Proof";
    subtitle = "Computationally infeasible to crack with today's hardware, even with dedicated supercomputers.";
  } else if (fastSecs >= SECONDS_PER_YEAR) {
    tier = "strong";
    badgeLabel = "Strong";
    subtitle = "Resistant to modern offline GPU cracking clusters under standard threat models.";
  } else if (fastSecs >= 86400) {
    tier = "moderate";
    badgeLabel = "Moderate";
    subtitle = "May withstand quick attacks, but vulnerable in an offline database breach over days or weeks.";
  } else if (fastSecs >= 60) {
    tier = "high-risk";
    badgeLabel = "High Risk";
    subtitle = "High risk: easily cracked in minutes or hours on consumer graphics cards.";
  }

  return {
    tier,
    badgeLabel,
    primaryTime: fastScenario.formatted,
    formattedFastGpu: fastScenario.formatted,
    formattedSlowHash: slowScenario.formatted,
    formattedOnline: onlineScenario.formatted,
    subtitle
  };
}

function formatSecondsDuration(seconds) {
  if (seconds <= 0 || !isFinite(seconds)) return "Instantly";
  if (seconds < 1) return "Instantly (< 1 sec)";
  if (seconds < 60) {
    const s = Math.round(seconds);
    return `${s} second${s === 1 ? "" : "s"}`;
  }

  const minutes = seconds / 60;
  if (minutes < 60) {
    const m = Math.round(minutes);
    return `${m} minute${m === 1 ? "" : "s"}`;
  }

  const hours = minutes / 60;
  if (hours < 24) {
    const h = Math.round(hours);
    return `${h} hour${h === 1 ? "" : "s"}`;
  }

  const days = hours / 24;
  if (days < 30) {
    const d = Math.round(days);
    return `${d} day${d === 1 ? "" : "s"}`;
  }

  const months = days / 30.4375;
  if (months < 12) {
    const mo = Math.round(months);
    return `${mo} month${mo === 1 ? "" : "s"}`;
  }

  const years = days / 365.25;
  return formatYearQuantity(years);
}

function toSuperscript(num) {
  const map = {
    "0": "⁰",
    "1": "¹",
    "2": "²",
    "3": "³",
    "4": "⁴",
    "5": "⁵",
    "6": "⁶",
    "7": "⁷",
    "8": "⁸",
    "9": "⁹",
    "-": "⁻"
  };
  return String(num)
    .split("")
    .map(ch => map[ch] || ch)
    .join("");
}

function formatScientificYears(log10Years) {
  let exp = Math.floor(log10Years);
  let mantissa = Math.pow(10, log10Years - exp);
  let rounded = mantissa.toFixed(1);
  if (parseFloat(rounded) >= 10.0) {
    exp += 1;
    rounded = "1.0";
  }
  return `${rounded} × 10${toSuperscript(exp)} years`;
}

function formatYearQuantity(years) {
  if (years < 1000) {
    const y = Math.round(years);
    if (y >= 1000) return "1 thousand years";
    return `${y} year${y === 1 ? "" : "s"}`;
  }
  if (years < 1e6) {
    const k = Math.round(years / 1000);
    if (k >= 1000) return "1 million years";
    return `${k} thousand years`;
  }
  if (years < 1e9) {
    const mVal = years / 1e6;
    if (Math.round(mVal) >= 1000) return "1 billion years";
    const m = mVal.toFixed(years < 1e7 ? 1 : 0);
    return `${m} million years`;
  }
  if (years < 1e12) {
    const bVal = years / 1e9;
    if (Math.round(bVal) >= 1000) return "1 trillion years";
    const b = bVal.toFixed(years < 1e10 ? 1 : 0);
    return `${b} billion years`;
  }
  if (years < 1e15) {
    const tVal = years / 1e12;
    if (Math.round(tVal) >= 1000) return "1 quadrillion years";
    const t = tVal.toFixed(years < 1e13 ? 1 : 0);
    return `${t} trillion years`;
  }
  if (years < 1e18) {
    const qVal = years / 1e15;
    if (Math.round(qVal) >= 1000) return "1 quintillion years";
    const q = qVal.toFixed(years < 1e16 ? 1 : 0);
    return `${q} quadrillion years`;
  }
  if (years < 1e21) {
    const qnVal = years / 1e18;
    if (Math.round(qnVal) >= 1000) return formatScientificYears(21);
    const qn = qnVal.toFixed(years < 1e19 ? 1 : 0);
    return `${qn} quintillion years`;
  }
  return formatScientificYears(Math.log10(years));
}

function formatLogYears(log10Years) {
  if (log10Years < 3) {
    return formatYearQuantity(Math.pow(10, log10Years));
  }
  if (log10Years < 6) {
    const k = Math.round(Math.pow(10, log10Years - 3));
    if (k >= 1000) return "1 million years";
    return `${k} thousand years`;
  }
  if (log10Years < 9) {
    const mVal = Math.pow(10, log10Years - 6);
    if (Math.round(mVal) >= 1000) return "1 billion years";
    const m = mVal.toFixed(log10Years < 7 ? 1 : 0);
    return `${m} million years`;
  }
  if (log10Years < 12) {
    const bVal = Math.pow(10, log10Years - 9);
    if (Math.round(bVal) >= 1000) return "1 trillion years";
    const b = bVal.toFixed(log10Years < 10 ? 1 : 0);
    return `${b} billion years`;
  }
  if (log10Years < 15) {
    const tVal = Math.pow(10, log10Years - 12);
    if (Math.round(tVal) >= 1000) return "1 quadrillion years";
    const t = tVal.toFixed(log10Years < 13 ? 1 : 0);
    return `${t} trillion years`;
  }
  if (log10Years < 18) {
    const qVal = Math.pow(10, log10Years - 15);
    if (Math.round(qVal) >= 1000) return "1 quintillion years";
    const q = qVal.toFixed(log10Years < 16 ? 1 : 0);
    return `${q} quadrillion years`;
  }
  if (log10Years < 21) {
    const qnVal = Math.pow(10, log10Years - 18);
    if (Math.round(qnVal) >= 1000) return formatScientificYears(21);
    const qn = qnVal.toFixed(log10Years < 19 ? 1 : 0);
    return `${qn} quintillion years`;
  }
  return formatScientificYears(log10Years);
}

function renderMeter(analysis) {
  const score = analysis.score;
  const entropy = analysis.adjustedEntropy;
  const percent = Math.min(100, Math.max(0, Math.round((entropy / 100) * 100)));

  let color = "var(--accent-weak)";
  let label = "-";
  switch (score) {
    case 0:
      color = "var(--accent-weak)";
      label = "Very Weak";
      break;
    case 1:
      color = "var(--accent-weak)";
      label = "Weak";
      break;
    case 2:
      color = "var(--accent-mid)";
      label = "Fair";
      break;
    case 3:
      color = "var(--accent-good)";
      label = "Good";
      break;
    case 4:
      color = "var(--accent-strong)";
      label = "Very Good";
      break;
    case 5:
      color = "var(--accent-strong)";
      label = "Excellent";
      break;
  }

  const visualPercent = analysis.length === 0 ? 0 : Math.min(100, Math.max(6, percent));
  meterBar.style.width = visualPercent + "%";
  meterBar.style.backgroundColor = color;

  if (analysis.length === 0) {
    strengthText.textContent = "Strength: -";
  } else {
    strengthText.textContent = `Strength: ${label} (${Math.round(analysis.adjustedEntropy)} bits entropy)`;
  }
}

function renderCrackTime(analysis, pw) {
  const ct = analysis.crackTimes;

  crackBadge.textContent = ct.badgeLabel;
  crackBadge.className = `crack-badge ${ct.tier}`;

  crackPrimaryTime.textContent = ct.primaryTime;
  crackPrimarySubtitle.textContent = ct.subtitle;

  if (ct.tier === "vulnerable" || ct.tier === "high-risk") {
    crackPrimaryTime.style.color = "var(--accent-weak)";
  } else if (ct.tier === "moderate") {
    crackPrimaryTime.style.color = "var(--accent-mid)";
  } else if (ct.tier === "strong") {
    crackPrimaryTime.style.color = "var(--accent-good)";
  } else if (ct.tier === "future-proof") {
    crackPrimaryTime.style.color = "var(--accent-strong)";
  } else {
    crackPrimaryTime.style.color = "var(--muted)";
  }

  timeFastGpu.textContent = ct.formattedFastGpu;
  timeSlowHash.textContent = ct.formattedSlowHash;
  timeOnline.textContent = ct.formattedOnline;
}

function renderChecks(pw, analysis = null) {
  if (!analysis) analysis = analyzePassword(pw);

  const isEmpty = pw.length === 0;

  // Group 1: Character Composition (5 items)
  const compItems = [
    {
      label: pw.length >= 16
        ? `Length: ${pw.length} characters (16+ ideal)`
        : `Length: ${pw.length} characters (12+ recommended)`,
      status: isEmpty ? "pending" : (pw.length >= 12 ? "ok" : "warn")
    },
    {
      label: "Contains lowercase letters (a-z)",
      status: isEmpty ? "pending" : (analysis.hasLower ? "ok" : "warn")
    },
    {
      label: "Contains uppercase letters (A-Z)",
      status: isEmpty ? "pending" : (analysis.hasUpper ? "ok" : "warn")
    },
    {
      label: "Contains numeric digits (0-9)",
      status: isEmpty ? "pending" : (analysis.hasDigit ? "ok" : "warn")
    },
    {
      label: "Contains special characters (!@#$...)",
      status: isEmpty ? "pending" : (analysis.hasSymbol ? "ok" : "warn")
    }
  ];

  // Group 2: Pattern & Vulnerability Defenses (5 items)
  const defenseItems = [
    {
      label: !isEmpty && analysis.isCommon
        ? "Found in common breach wordlists"
        : "Not found in common dictionaries",
      status: isEmpty ? "pending" : (analysis.isCommon ? "bad" : "ok")
    },
    {
      label: !isEmpty && (analysis.repeats > 0 || analysis.pureSame)
        ? "Avoid repeated characters or sequences"
        : "No obvious repeated character sequences",
      status: isEmpty ? "pending" : ((analysis.repeats === 0 && !analysis.pureSame) ? "ok" : "bad")
    },
    {
      label: !isEmpty && (analysis.seqs > 0 || analysis.pureSequence)
        ? "Avoid sequential characters (e.g. 1234, abcd)"
        : "No obvious sequential characters",
      status: isEmpty ? "pending" : ((analysis.seqs === 0 && !analysis.pureSequence) ? "ok" : "bad")
    },
    {
      label: !isEmpty && (analysis.keyboardSeqs > 0 || analysis.pureKeyboard)
        ? "Avoid keyboard path walks (e.g. qwerty, asdf)"
        : "No keyboard walk patterns",
      status: isEmpty ? "pending" : ((analysis.keyboardSeqs === 0 && !analysis.pureKeyboard) ? "ok" : "bad")
    },
    {
      label: isEmpty
        ? "High character variety (unique characters)"
        : (pw.length >= 6 && analysis.diversityRatio < 0.5
            ? "Low character variety (too repetitive)"
            : (pw.length >= 6
                ? `Good variety (${analysis.uniqueChars} unique characters)`
                : "Add more unique characters")),
      status: isEmpty ? "pending" : (pw.length >= 6 && analysis.diversityRatio >= 0.5 ? "ok" : (pw.length >= 6 ? "bad" : "warn"))
    }
  ];

  const allItems = [...compItems, ...defenseItems];
  const passedCount = allItems.filter(it => it.status === "ok").length;
  const totalCount = allItems.length;

  checksList.innerHTML = "";

  // Header with title and counter badge
  const header = document.createElement("div");
  header.className = "checks-header";

  const title = document.createElement("span");
  title.className = "checks-title";
  title.textContent = "Security Checklist";

  const badge = document.createElement("span");
  badge.className = "checks-badge";
  if (isEmpty) {
    badge.textContent = `0 of ${totalCount} passed`;
  } else if (passedCount === totalCount) {
    badge.className = "checks-badge all-good";
    badge.textContent = `${totalCount} of ${totalCount} passed (All clear!)`;
  } else {
    badge.className = `checks-badge ${passedCount >= 8 ? "all-good" : "partial"}`;
    badge.textContent = `${passedCount} of ${totalCount} passed`;
  }

  header.appendChild(title);
  header.appendChild(badge);
  checksList.appendChild(header);

  // Responsive 2-column grid
  const grid = document.createElement("div");
  grid.className = "checks-grid";

  grid.appendChild(createCheckGroup("Composition & Length", compItems));
  grid.appendChild(createCheckGroup("Pattern & Threat Defenses", defenseItems));
  checksList.appendChild(grid);

  // Suggestions card
  if (!isEmpty && analysis.suggestions && analysis.suggestions.length > 0) {
    const hasWarnings = analysis.suggestions.some(
      s => !s.startsWith("Excellent password")
    );
    const isSuccess = passedCount === totalCount && !hasWarnings;
    const card = document.createElement("div");
    card.className = `suggestions-card ${isSuccess ? "success" : ""}`;

    const head = document.createElement("div");
    head.className = "suggestions-header";
    head.innerHTML = isSuccess
      ? `<span>🛡️</span> Security Analysis:`
      : (passedCount === totalCount
          ? `<span>🛡️</span> Security Analysis & Advisory:`
          : `<span>💡</span> Actionable Recommendations:`);
    card.appendChild(head);

    const ul = document.createElement("ul");
    ul.className = "suggestions-list";
    for (const s of analysis.suggestions) {
      const li = document.createElement("li");
      li.textContent = s;
      ul.appendChild(li);
    }
    card.appendChild(ul);
    checksList.appendChild(card);
  }
}

function createCheckGroup(groupTitle, items) {
  const group = document.createElement("div");
  group.className = "checks-group";

  const title = document.createElement("div");
  title.className = "checks-group-title";
  title.textContent = groupTitle;
  group.appendChild(title);

  const ul = document.createElement("ul");
  ul.className = "checks-list";

  for (const it of items) {
    const li = document.createElement("li");
    li.className = `check-item ${it.status}`;

    const icon = document.createElement("span");
    icon.className = "check-icon";
    icon.setAttribute("aria-hidden", "true");

    if (it.status === "ok") {
      icon.textContent = "✓";
    } else if (it.status === "bad") {
      icon.textContent = "✕";
    } else if (it.status === "warn") {
      icon.textContent = "•";
    } else {
      icon.textContent = "○";
    }

    const txt = document.createElement("span");
    txt.textContent = it.label;

    li.appendChild(icon);
    li.appendChild(txt);
    ul.appendChild(li);
  }

  group.appendChild(ul);
  return group;
}

/* Pattern detection utilities */

function isAllSameChar(s) {
  if (s.length <= 1) return false;
  for (let i = 1; i < s.length; i++) {
    if (s[i] !== s[0]) return false;
  }
  return true;
}

function isPureSequence(s) {
  if (s.length < 3) return false;
  let isAsc = true;
  let isDesc = true;
  for (let i = 1; i < s.length; i++) {
    const diff = s.charCodeAt(i) - s.charCodeAt(i - 1);
    if (diff !== 1) isAsc = false;
    if (diff !== -1) isDesc = false;
  }
  return isAsc || isDesc;
}

function isPureKeyboardWalk(s) {
  if (s.length < 3) return false;
  const lower = s.toLowerCase();
  const rows = [
    "1234567890-=",
    "qwertyuiop[]\\",
    "asdfghjkl;'",
    "zxcvbnm,./"
  ];
  for (const row of rows) {
    if (row.includes(lower) || row.split("").reverse().join("").includes(lower)) {
      return true;
    }
  }
  return false;
}

function countRepeatedSequences(s) {
  if (!s) return 0;
  let repeats = 0;
  let run = 1;
  for (let i = 1; i < s.length; i++) {
    if (s[i] === s[i - 1]) run++;
    else {
      if (run > 2) repeats++;
      run = 1;
    }
  }
  if (run > 2) repeats++;

  // Detect repeated chunks of length 2 to 4 (e.g. "abab", "abcabc", "1212")
  for (let len = 2; len <= 4; len++) {
    for (let i = 0; i + len * 2 <= s.length; i++) {
      const part = s.slice(i, i + len);
      const next = s.slice(i + len, i + len * 2);
      if (part && part === next) repeats++;
    }
  }
  return Math.max(0, repeats);
}

function countSequentialRuns(s) {
  if (!s || s.length < 3) return 0;
  let runs = 0;
  let runLen = 1;
  let currentDirection = 0;

  for (let i = 1; i < s.length; i++) {
    const diff = s.charCodeAt(i) - s.charCodeAt(i - 1);
    if (diff === 1 || diff === -1) {
      if (currentDirection === 0) {
        currentDirection = diff;
        runLen = 2;
      } else if (currentDirection === diff) {
        runLen++;
      } else {
        // Monotonic direction reversed: evaluate previous run and start new direction
        if (runLen >= 3) runs++;
        currentDirection = diff;
        runLen = 2;
      }
    } else {
      if (runLen >= 3) runs++;
      runLen = 1;
      currentDirection = 0;
    }
  }
  if (runLen >= 3) runs++;
  return runs;
}

function countKeyboardSequences(s) {
  if (!s) return 0;
  const lower = s.toLowerCase();
  const keyboardPatterns = [
    "qwerty",
    "asdf",
    "zxcv",
    "12345",
    "!@#$%",
    "qaz",
    "wsx"
  ];
  let found = 0;
  for (const p of keyboardPatterns) {
    if (lower.includes(p)) found++;
  }
  return found;
}

/* Context-aware, personalized security recommendations */
function generateActionableRecommendations(pw, a) {
  const suggestions = [];
  const length = pw.length;
  if (length === 0) return suggestions;

  // 1. Length recommendation with exact count needed
  if (length < 8) {
    suggestions.push(`Currently only ${length} characters. Add at least ${12 - length} more characters (aim for 16+ for long-term defense).`);
  } else if (length < 12) {
    const diff = 12 - length;
    suggestions.push(`Currently ${length} characters. Adding ${diff} more character${diff === 1 ? "" : "s"} reaches the 12-character recommended threshold.`);
  }

  // 2. Character composition recommendations
  const missingClasses = [];
  if (!a.hasLower) missingClasses.push("lowercase letters (a-z)");
  if (!a.hasUpper) missingClasses.push("uppercase letters (A-Z)");
  if (!a.hasDigit) missingClasses.push("numeric digits (0-9)");
  if (!a.hasSymbol) missingClasses.push("special symbols (!@#$%...)");

  if (missingClasses.length > 0) {
    suggestions.push(`Expand character variety by adding: ${missingClasses.join(", ")}.`);
  }

  // 3. Dictionary & wordlist match
  if (a.isCommon) {
    suggestions.unshift("Matches a common breached password or dictionary stem. Switch to an unpredictable multi-word passphrase.");
  }

  // 4. Repeated sequences with detected sample
  if (a.repeats > 0 || a.pureSame) {
    const repeatMatch = pw.match(/(.)\1{2,}/) || pw.match(/(.{2,4})\1+/);
    const sample = repeatMatch ? ` (e.g. '${repeatMatch[0]}')` : "";
    suggestions.push(`Avoid repeating character chunks${sample}. Repetitions severely reduce search complexity.`);
  }

  // 5. Sequential runs with detected sample
  if (a.seqs > 0 || a.pureSequence) {
    const seqMatch = findSequentialSample(pw);
    const sample = seqMatch ? ` (e.g. '${seqMatch}')` : "";
    suggestions.push(`Avoid sequential alphabet or number runs${sample}. Automated tools test sequences first.`);
  }

  // 6. Keyboard walks with detected sample
  if (a.keyboardSeqs > 0 || a.pureKeyboard) {
    const kbMatch = findKeyboardSample(pw);
    const sample = kbMatch ? ` (e.g. '${kbMatch}')` : "";
    suggestions.push(`Avoid keyboard walk patterns${sample}. Spatial keyboard paths are among the first patterns tested by cracking dictionaries.`);
  }

  // 7. Year detection
  const yearMatch = pw.match(/(19\d\d|20[0-3]\d)/);
  if (yearMatch) {
    suggestions.push(`Contains a 4-digit year pattern ('${yearMatch[0]}'). Avoid birth years or current dates, as rule-based cracking tools specifically target them.`);
  }

  // 8. Low character diversity
  if (length >= 6 && a.diversityRatio < 0.5) {
    suggestions.push(`Low variety: only ${a.uniqueChars} unique characters used out of ${length}. Mix in different characters across the string.`);
  }

  // 9. All good praise
  if (suggestions.length === 0 && length >= 12) {
    suggestions.push("Excellent password! All 10 security checks satisfied. It resists dictionary attacks, pattern searches, and modern GPU cracking clusters.");
  }

  return suggestions;
}

function findSequentialSample(s) {
  for (let i = 2; i < s.length; i++) {
    const c1 = s.charCodeAt(i - 2);
    const c2 = s.charCodeAt(i - 1);
    const c3 = s.charCodeAt(i);
    if ((c2 === c1 + 1 && c3 === c2 + 1) || (c2 === c1 - 1 && c3 === c2 - 1)) {
      return s.slice(i - 2, i + 1);
    }
  }
  return null;
}

function findKeyboardSample(s) {
  const lower = s.toLowerCase();
  const keyboardPatterns = ["qwerty", "asdf", "zxcv", "12345", "!@#$%", "qaz", "wsx"];
  for (const p of keyboardPatterns) {
    if (lower.includes(p)) return p;
  }
  return null;
}

// Cryptographically secure random integer generation with rejection sampling
function getCryptoRandomInt(max) {
  if (window.crypto && window.crypto.getRandomValues) {
    const limit = Math.floor(0x100000000 / max) * max;
    const uintArray = new Uint32Array(1);
    do {
      window.crypto.getRandomValues(uintArray);
    } while (uintArray[0] >= limit);
    return uintArray[0] % max;
  }
  return Math.floor(Math.random() * max);
}

// Unbiased Fisher-Yates shuffle using CSPRNG
function cryptoShuffle(array) {
  for (let i = array.length - 1; i > 0; i--) {
    const j = getCryptoRandomInt(i + 1);
    const temp = array[i];
    array[i] = array[j];
    array[j] = temp;
  }
  return array;
}

function generatePassword() {
  const length = 16;
  const lowers = "abcdefghijklmnopqrstuvwxyz";
  const uppers = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  const digits = "0123456789";
  const symbols = "!@#$%^&*()-_=+[]{};:,.<>?";
  const all = lowers + uppers + digits + symbols;

  const pick = (set) => set[getCryptoRandomInt(set.length)];
  const chars = [];
  chars.push(pick(lowers));
  chars.push(pick(uppers));
  chars.push(pick(digits));
  chars.push(pick(symbols));
  for (let i = 4; i < length; i++) {
    chars.push(pick(all));
  }

  const out = cryptoShuffle(chars).join("");
  passwordEl.value = out;
  passwordEl.type = "text";
  toggleVis.setAttribute("aria-pressed", "true");
  toggleVis.textContent = "Hide";
  onInput();
}

function toggleVisibility() {
  const isPwd = passwordEl.type === "password";
  passwordEl.type = isPwd ? "text" : "password";
  toggleVis.setAttribute("aria-pressed", String(isPwd));
  toggleVis.textContent = isPwd ? "Hide" : "Show";
}

let copyTimeoutId = null;

async function copyPassword() {
  const value = passwordEl.value;
  if (!value) {
    if (copyTimeoutId) clearTimeout(copyTimeoutId);
    copyBtn.textContent = "No password";
    copyTimeoutId = setTimeout(() => {
      copyBtn.textContent = "Copy password";
      copyTimeoutId = null;
    }, 1500);
    return;
  }

  if (copyTimeoutId) clearTimeout(copyTimeoutId);

  try {
    await navigator.clipboard.writeText(value);
    copyBtn.textContent = "Copied";
  } catch (e) {
    try {
      passwordEl.select();
      document.execCommand("copy");
      copyBtn.textContent = "Copied";
    } catch (err) {
      copyBtn.textContent = "Copy failed";
    }
  }

  copyTimeoutId = setTimeout(() => {
    copyBtn.textContent = "Copy password";
    copyTimeoutId = null;
  }, 1500);
}

function clearPassword() {
  passwordEl.value = "";
  passwordEl.type = "password";
  toggleVis.textContent = "Show";
  toggleVis.setAttribute("aria-pressed", "false");
  onInput();
}

// Theme Switcher Initialization
const themeToggle = document.getElementById("themeToggle");
if (themeToggle) {
  let savedTheme = null;
  try {
    savedTheme = localStorage.getItem("theme");
  } catch (e) {
    // LocalStorage access restricted
  }
  const initialTheme = savedTheme || "light";
  document.documentElement.setAttribute("data-theme", initialTheme);

  themeToggle.addEventListener("click", () => {
    const currentTheme = document.documentElement.getAttribute("data-theme") || "light";
    const nextTheme = currentTheme === "dark" ? "light" : "dark";
    document.documentElement.setAttribute("data-theme", nextTheme);
    try {
      localStorage.setItem("theme", nextTheme);
    } catch (e) {
      // LocalStorage access restricted
    }
  });
}

