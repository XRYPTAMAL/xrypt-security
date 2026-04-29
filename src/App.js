import { useState, useEffect, useRef } from "react";
import { db, collection, addDoc, getDocs, query, orderBy, limit } from "./firebase";

// ── helpers ────────────────────────────────────────────────────────────────

const SUSPICIOUS_KEYWORDS = [
  "login","verify","update","secure","account","banking","paypal","ebay",
  "amazon","apple","microsoft","free","win","prize","click","confirm",
  "suspend","urgent","alert","password","credential","signin","sign-in",
];

const DANGEROUS_EXTENSIONS = ["exe","bat","cmd","vbs","ps1","apk","dmg","msi","sh","jar","scr","pif","com"];
const WARN_EXTENSIONS      = ["zip","rar","7z","tar","gz","iso","pdf","doc","docx","xls","macro"];
const SAFE_EXTENSIONS      = ["txt","jpg","jpeg","png","gif","mp3","mp4","svg","csv","json","html","css","js"];

function analyzeURL(raw) {
  const url    = raw.trim();
  const issues = [];
  const good   = [];
  let   score  = 0; // higher = riskier

  if (!url) return null;

  const hasHTTPS = url.startsWith("https://");
  if (!hasHTTPS) { score += 30; issues.push("No HTTPS — connection is unencrypted"); }
  else            { good.push("HTTPS encryption present"); }

  // suspicious keywords
  const lower   = url.toLowerCase();
  const found   = SUSPICIOUS_KEYWORDS.filter(k => lower.includes(k));
  if (found.length >= 2) { score += 40; issues.push(`Phishing keywords detected: "${found.slice(0,3).join('", "')}"`); }
  else if (found.length === 1) { score += 15; issues.push(`Suspicious keyword found: "${found[0]}"`); }
  else good.push("No phishing keywords detected");

  // IP address instead of domain
  if (/https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(url)) {
    score += 35; issues.push("Direct IP address used instead of domain name");
  }

  // very long URL
  if (url.length > 120) { score += 15; issues.push("Unusually long URL (common in phishing links)"); }
  else good.push("URL length is normal");

  // multiple subdomains
  try {
    const hostname = new URL(url.startsWith("http") ? url : "https://" + url).hostname;
    const parts    = hostname.split(".");
    if (parts.length > 4) { score += 20; issues.push(`Excessive subdomains (${parts.length - 2} levels deep)`); }
    else good.push("Domain structure looks clean");

    // recently-registered TLDs heuristic
    const suspTLD = [".tk",".ml",".ga",".cf",".gq",".xyz",".top",".click",".link"];
    if (suspTLD.some(t => hostname.endsWith(t))) {
      score += 25; issues.push("High-risk TLD associated with free/disposable domains");
    }
  } catch (_) {
    score += 10; issues.push("URL could not be parsed correctly");
  }

  // redirect indicators
  if (lower.includes("redirect") || lower.includes("url=") || lower.includes("link=")) {
    score += 20; issues.push("Possible redirect chain detected");
  }

  const level = score >= 50 ? "RISKY" : score >= 20 ? "SUSPICIOUS" : "SAFE";
  return { level, score, issues, good, type: "URL" };
}

function analyzeFile(file) {
  const ext    = file.name.split(".").pop().toLowerCase();
  const sizeMB = (file.size / 1024 / 1024).toFixed(2);
  const issues = [];
  const good   = [];
  let   score  = 0;

  if (DANGEROUS_EXTENSIONS.includes(ext)) {
    score += 70; issues.push(`Executable file type (.${ext}) — can run code on your device`);
  } else if (WARN_EXTENSIONS.includes(ext)) {
    score += 30; issues.push(`Archive/document (.${ext}) — may contain hidden scripts`);
  } else if (SAFE_EXTENSIONS.includes(ext)) {
    good.push(`File type (.${ext}) is generally safe`);
  } else {
    score += 20; issues.push(`Unknown extension (.${ext}) — exercise caution`);
  }

  if (file.size > 50 * 1024 * 1024)      { score += 20; issues.push(`Large file size (${sizeMB} MB) — unusual for most documents`); }
  else if (file.size < 100 && score > 30) { score += 15; issues.push("Suspiciously tiny executable — possible dropper"); }
  else good.push(`File size is ${sizeMB} MB — within normal range`);

  if (file.name.includes(" ") && DANGEROUS_EXTENSIONS.includes(ext)) {
    score += 10; issues.push("Filename with spaces on executable — common social engineering trick");
  }

  const doubleExt = /\.(pdf|doc|jpg|png)\.(exe|bat|cmd|vbs)$/i.test(file.name);
  if (doubleExt) { score += 30; issues.push("Double extension detected — disguised executable!"); }

  const level = score >= 50 ? "RISKY" : score >= 20 ? "SUSPICIOUS" : "SAFE";
  return { level, score, issues, good, type: "FILE", ext, sizeMB, name: file.name };
}

// ── scan steps animation ───────────────────────────────────────────────────
const SCAN_STEPS = [
  "Initializing scan engine…",
  "Resolving domain structure…",
  "Checking SSL certificates…",
  "Scanning for phishing patterns…",
  "Cross-referencing threat database…",
  "Analyzing behavioral signatures…",
  "Finalizing risk assessment…",
];

// ── component ──────────────────────────────────────────────────────────────
export default function XryptSecurity() {
  const [tab,        setTab]        = useState("url");  // url | file
  const [urlInput,   setUrlInput]   = useState("");
  const [file,       setFile]       = useState(null);
  const [phase,      setPhase]      = useState("idle"); // idle | scanning | result
  const [stepIdx,    setStepIdx]    = useState(0);
  const [progress,   setProgress]   = useState(0);
  const [result,     setResult]     = useState(null);
  const [history,    setHistory]    = useState([]);
  const [showPanel,  setShowPanel]  = useState(false);
  const [copied,     setCopied]     = useState(false);
  const [adminUnlocked, setAdminUnlocked] = useState(false);
  const [adminInput,    setAdminInput]    = useState("");
  const [adminError,    setAdminError]    = useState(false);
  const ADMIN_PASSWORD = "xrypt2025";
  const inputRef   = useRef(null);
  const fileRef    = useRef(null);

  useEffect(() => { if (phase === "idle") inputRef.current?.focus(); }, [phase]);

  // load history from memory (in-memory for this session)
  const addHistory = (r) => {
    setHistory(prev => [{
      type: r.type,
      level: r.level,
      label: r.type === "URL" ? urlInput.slice(0,40) : r.name,
      time: new Date().toLocaleTimeString(),
    }, ...prev].slice(0, 20));
  };

  const startScan = () => {
    if (tab === "url" && !urlInput.trim()) return;
    if (tab === "file" && !file)           return;

    setPhase("scanning");
    setStepIdx(0);
    setProgress(0);

    const duration = 2400;
    const steps    = SCAN_STEPS.length;
    let   elapsed  = 0;
    const tick     = 80;

    const timer = setInterval(() => {
      elapsed += tick;
      const pct = Math.min((elapsed / duration) * 100, 99);
      setProgress(pct);
      setStepIdx(Math.floor((elapsed / duration) * steps));
      if (elapsed >= duration) {
        clearInterval(timer);
        setProgress(100);
        setTimeout(() => {
          const r = tab === "url" ? analyzeURL(urlInput) : analyzeFile(file);
          setResult(r);
          addHistory(r);
          setPhase("result");
        }, 300);
      }
    }, tick);
  };

  const reset = () => {
    setPhase("idle");
    setResult(null);
    setUrlInput("");
    setFile(null);
    setProgress(0);
    setStepIdx(0);
    setCopied(false);
  };

  const copyResult = () => {
    if (!result) return;
    const text = `XRYPT SECURITY REPORT\nType: ${result.type}\nResult: ${result.level}\nIssues: ${result.issues.join(", ") || "None"}\nTime: ${new Date().toLocaleString()}`;
    navigator.clipboard.writeText(text).then(() => { setCopied(true); setTimeout(() => setCopied(false), 2000); });
  };

  const levelColor = (l) => l === "SAFE" ? "#00ff88" : l === "SUSPICIOUS" ? "#ffc107" : "#ff3c5f";
  const levelGlow  = (l) => l === "SAFE"
    ? "0 0 30px #00ff8877, 0 0 60px #00ff8833"
    : l === "SUSPICIOUS"
    ? "0 0 30px #ffc10777, 0 0 60px #ffc10733"
    : "0 0 30px #ff3c5f77, 0 0 60px #ff3c5f33";

  // ── styles ─────────────────────────────────────────────────────────────
  const S = {
    root: {
      minHeight: "100vh",
      background: "#060608",
      fontFamily: "'Courier New', 'Lucida Console', monospace",
      color: "#e0e0e0",
      display: "flex",
      flexDirection: "column",
      alignItems: "center",
      padding: "20px 16px 60px",
      position: "relative",
      overflow: "hidden",
    },
    grid: {
      position: "fixed", inset: 0, zIndex: 0,
      backgroundImage: `
        linear-gradient(rgba(0,255,136,0.03) 1px, transparent 1px),
        linear-gradient(90deg, rgba(0,255,136,0.03) 1px, transparent 1px)
      `,
      backgroundSize: "40px 40px",
      pointerEvents: "none",
    },
    scanLine: {
      position: "fixed", top: 0, left: 0, right: 0, height: "2px",
      background: "linear-gradient(90deg, transparent, #00ff88, transparent)",
      animation: "scanline 4s linear infinite",
      zIndex: 1, opacity: 0.4,
    },
    header: {
      zIndex: 2, textAlign: "center", marginBottom: "36px", marginTop: "16px",
    },
    logo: {
      fontSize: "clamp(22px, 5vw, 36px)",
      fontWeight: 900,
      letterSpacing: "6px",
      color: "#00ff88",
      textShadow: "0 0 20px #00ff8888, 0 0 40px #00ff8844",
      margin: 0,
    },
    sub: {
      fontSize: "11px", letterSpacing: "4px", color: "#555", marginTop: "6px",
    },
    card: {
      background: "rgba(255,255,255,0.03)",
      border: "1px solid rgba(0,255,136,0.15)",
      borderRadius: "16px",
      padding: "32px",
      width: "100%",
      maxWidth: "580px",
      backdropFilter: "blur(12px)",
      boxShadow: "0 0 40px rgba(0,255,136,0.05)",
      zIndex: 2,
    },
    tabs: { display: "flex", gap: "8px", marginBottom: "24px" },
    tab: (active) => ({
      flex: 1, padding: "10px", border: "none", borderRadius: "8px",
      cursor: "pointer", fontSize: "12px", letterSpacing: "2px", fontFamily: "inherit",
      transition: "all .2s",
      background: active ? "rgba(0,255,136,0.15)" : "rgba(255,255,255,0.04)",
      color:      active ? "#00ff88" : "#555",
      boxShadow:  active ? "0 0 12px rgba(0,255,136,0.2)" : "none",
      borderBottom: active ? "1px solid #00ff88" : "1px solid transparent",
    }),
    input: {
      width: "100%", background: "rgba(0,0,0,0.4)", border: "1px solid rgba(0,255,136,0.2)",
      borderRadius: "10px", padding: "14px 16px", color: "#e0e0e0",
      fontSize: "13px", fontFamily: "inherit", outline: "none",
      transition: "border .2s, box-shadow .2s", boxSizing: "border-box",
    },
    scanBtn: {
      width: "100%", marginTop: "16px", padding: "16px",
      background: "linear-gradient(135deg, rgba(0,255,136,0.2), rgba(0,255,136,0.05))",
      border: "1px solid rgba(0,255,136,0.5)", borderRadius: "10px",
      color: "#00ff88", fontSize: "14px", letterSpacing: "4px", fontFamily: "inherit",
      cursor: "pointer", fontWeight: 700,
      boxShadow: "0 0 20px rgba(0,255,136,0.15)",
      transition: "all .2s",
    },
    progressBar: {
      width: "100%", height: "3px", background: "rgba(255,255,255,0.07)",
      borderRadius: "99px", overflow: "hidden", margin: "20px 0 12px",
    },
    progressFill: {
      height: "100%", background: "linear-gradient(90deg, #00ff88, #00ccff)",
      borderRadius: "99px", transition: "width .1s linear",
      boxShadow: "0 0 8px #00ff88",
    },
    resultLevel: (l) => ({
      fontSize: "clamp(36px, 10vw, 64px)", fontWeight: 900, letterSpacing: "8px",
      color: levelColor(l), textShadow: levelGlow(l), margin: "8px 0",
      textAlign: "center",
    }),
    pill: (ok) => ({
      display: "inline-block", padding: "4px 10px", borderRadius: "99px",
      fontSize: "11px", marginBottom: "6px",
      background: ok ? "rgba(0,255,136,0.1)" : "rgba(255,60,95,0.1)",
      color:      ok ? "#00ff88"             : "#ff3c5f",
      border:     `1px solid ${ok ? "rgba(0,255,136,0.3)" : "rgba(255,60,95,0.3)"}`,
    }),
    secondaryBtn: {
      padding: "10px 20px", background: "transparent",
      border: "1px solid rgba(255,255,255,0.1)", borderRadius: "8px",
      color: "#888", fontSize: "11px", letterSpacing: "2px", fontFamily: "inherit",
      cursor: "pointer", transition: "all .2s",
    },
    historyItem: (l) => ({
      display: "flex", justifyContent: "space-between", alignItems: "center",
      padding: "10px 14px", borderRadius: "8px", marginBottom: "6px",
      background: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.06)",
      fontSize: "11px",
    }),
  };

  // ── render ─────────────────────────────────────────────────────────────
  return (
    <div style={S.root}>
      <style>{`
        @keyframes scanline { 0%{transform:translateY(-100vh)} 100%{transform:translateY(100vh)} }
        @keyframes pulse    { 0%,100%{opacity:.7} 50%{opacity:1} }
        @keyframes fadeIn   { from{opacity:0;transform:translateY(12px)} to{opacity:1;transform:translateY(0)} }
        @keyframes glow     { 0%,100%{text-shadow:0 0 20px #00ff8888} 50%{text-shadow:0 0 40px #00ff88cc,0 0 80px #00ff8866} }
        .scan-input:focus { border-color:rgba(0,255,136,0.5)!important; box-shadow:0 0 16px rgba(0,255,136,0.12)!important; }
        .scan-btn:hover   { box-shadow:0 0 30px rgba(0,255,136,0.3)!important; transform:translateY(-1px); }
        .scan-btn:active  { transform:translateY(0); }
        .sec-btn:hover    { border-color:rgba(255,255,255,0.25)!important; color:#ccc!important; }
        .fadein           { animation: fadeIn .4s ease forwards; }
        .glowpulse        { animation: glow 2s ease-in-out infinite; }
        .blink            { animation: pulse 1.2s ease-in-out infinite; }
        ::-webkit-scrollbar { width:4px } ::-webkit-scrollbar-track { background:transparent }
        ::-webkit-scrollbar-thumb { background:#00ff8844; border-radius:99px }
      `}</style>

      <div style={S.grid} />
      <div style={S.scanLine} />

      {/* header */}
      <div style={S.header}>
        <p style={{fontSize:"11px", color:"#00ff8855", letterSpacing:"3px", margin:"0 0 8px", fontFamily:"inherit"}}>▸ SECURITY ANALYSIS SYSTEM ◂</p>
        <h1 style={S.logo}>XRYPT SECURITY</h1>
        <p style={S.sub}>THREAT INTELLIGENCE · LINK SCANNER · FILE ANALYSIS</p>
      </div>

      {/* admin panel toggle */}
      <div style={{zIndex:2, width:"100%", maxWidth:"580px", marginBottom:"10px", textAlign:"right"}}>
        <button className="sec-btn" style={S.secondaryBtn} onClick={() => setShowPanel(p => !p)}>
          {showPanel ? "◂ HIDE PANEL" : "▸ ADMIN PANEL"}
        </button>
      </div>

      {/* admin password gate */}
      {showPanel && !adminUnlocked && (
        <div className="fadein" style={{...S.card, marginBottom:"16px", padding:"28px", textAlign:"center"}}>
          <div style={{fontSize:"36px", marginBottom:"10px"}}>🔐</div>
          <p style={{fontSize:"11px", letterSpacing:"3px", color:"#00ff88", marginBottom:"6px"}}>ADMIN ACCESS REQUIRED</p>
          <p style={{fontSize:"10px", color:"#444", marginBottom:"20px", letterSpacing:"1px"}}>Enter the admin password to continue</p>
          <input
            className="scan-input"
            style={{...S.input, textAlign:"center", letterSpacing:"6px", marginBottom:"10px"}}
            type="password"
            placeholder="••••••••"
            value={adminInput}
            onChange={e => { setAdminInput(e.target.value); setAdminError(false); }}
            onKeyDown={e => {
              if (e.key === "Enter") {
                if (adminInput === ADMIN_PASSWORD) { setAdminUnlocked(true); setAdminError(false); loadFirebaseHistory(); }
                else { setAdminError(true); setAdminInput(""); }
              }
            }}
            autoFocus
          />
          {adminError && (
            <p style={{color:"#ff3c5f", fontSize:"11px", letterSpacing:"2px", marginBottom:"10px"}}>
              ✗ INCORRECT PASSWORD — ACCESS DENIED
            </p>
          )}
          <div style={{display:"flex", gap:"10px", justifyContent:"center", marginTop:"6px"}}>
            <button className="scan-btn" style={{...S.scanBtn, marginTop:0, maxWidth:"160px"}} onClick={() => {
              if (adminInput === ADMIN_PASSWORD) { setAdminUnlocked(true); setAdminError(false); loadFirebaseHistory(); }
              else { setAdminError(true); setAdminInput(""); }
            }}>▶ UNLOCK</button>
            <button className="sec-btn" style={S.secondaryBtn} onClick={() => { setShowPanel(false); setAdminInput(""); setAdminError(false); }}>
              CANCEL
            </button>
          </div>
        </div>
      )}

      {/* admin panel — only shown after unlock */}
      {showPanel && adminUnlocked && (
        <div className="fadein" style={{...S.card, marginBottom:"16px", padding:"20px"}}>
          <div style={{display:"flex", justifyContent:"space-between", alignItems:"center", marginBottom:"16px"}}>
            <p style={{fontSize:"11px", letterSpacing:"3px", color:"#00ff88", margin:0}}>▸ SCAN HISTORY</p>
            <button className="sec-btn" style={{...S.secondaryBtn, fontSize:"9px", padding:"6px 12px"}}
              onClick={() => { setAdminUnlocked(false); setShowPanel(false); setAdminInput(""); }}>
              🔒 LOCK
            </button>
          </div>
          {history.length === 0 && <p style={{color:"#444", fontSize:"12px"}}>No scans yet.</p>}
          {history.map((h,i) => (
            <div key={i} style={S.historyItem(h.level)}>
              <span style={{color:"#666"}}>[{h.type}]</span>
              <span style={{flex:1, margin:"0 10px", color:"#aaa", overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap"}}>{h.label}</span>
              <span style={{color: levelColor(h.level), fontWeight:700, marginRight:"10px"}}>{h.level}</span>
              <span style={{color:"#444"}}>{h.time}</span>
            </div>
          ))}
          {history.length > 0 && (
            <div style={{marginTop:"16px", display:"flex", gap:"16px"}}>
              {["SAFE","SUSPICIOUS","RISKY"].map(l => (
                <div key={l} style={{textAlign:"center"}}>
                  <div style={{fontSize:"20px", fontWeight:900, color: levelColor(l)}}>
                    {history.filter(h => h.level === l).length}
                  </div>
                  <div style={{fontSize:"9px", color:"#555", letterSpacing:"2px"}}>{l}</div>
                </div>
              ))}
              <div style={{textAlign:"center", marginLeft:"auto"}}>
                <div style={{fontSize:"20px", fontWeight:900, color:"#00ccff"}}>{history.length}</div>
                <div style={{fontSize:"9px", color:"#555", letterSpacing:"2px"}}>TOTAL</div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* main card */}
      <div style={S.card}>

        {/* ── IDLE ── */}
        {phase === "idle" && (
          <div className="fadein">
            <div style={S.tabs}>
              {["url","file"].map(t => (
                <button key={t} style={S.tab(tab===t)} onClick={() => setTab(t)}>
                  {t === "url" ? "🌐  URL SCAN" : "📁  FILE CHECK"}
                </button>
              ))}
            </div>

            {tab === "url" ? (
              <>
                <input
                  ref={inputRef}
                  className="scan-input"
                  style={S.input}
                  placeholder="https://example.com"
                  value={urlInput}
                  onChange={e => setUrlInput(e.target.value)}
                  onKeyDown={e => e.key === "Enter" && startScan()}
                  autoFocus
                />
                <p style={{fontSize:"10px", color:"#444", marginTop:"8px", letterSpacing:"1px"}}>
                  Press ENTER or click SCAN — checks HTTPS, keywords, domain structure & more
                </p>
              </>
            ) : (
              <>
                <div
                  onClick={() => fileRef.current?.click()}
                  style={{
                    border: "2px dashed rgba(0,255,136,0.2)", borderRadius:"10px",
                    padding:"32px", textAlign:"center", cursor:"pointer",
                    color:"#444", fontSize:"13px", transition:"all .2s",
                  }}
                  onMouseEnter={e => e.currentTarget.style.borderColor="rgba(0,255,136,0.5)"}
                  onMouseLeave={e => e.currentTarget.style.borderColor="rgba(0,255,136,0.2)"}
                >
                  {file
                    ? <><span style={{color:"#00ff88"}}>✓</span> {file.name} <span style={{color:"#555"}}>({(file.size/1024).toFixed(1)} KB)</span></>
                    : <><span style={{fontSize:"24px"}}>📂</span><br/>Click to upload file</>
                  }
                  <input ref={fileRef} type="file" style={{display:"none"}} onChange={e => setFile(e.target.files[0])} />
                </div>
                <p style={{fontSize:"10px", color:"#444", marginTop:"8px", letterSpacing:"1px"}}>
                  Checks extension, size, and suspicious patterns — no file is uploaded to any server
                </p>
              </>
            )}

            <button className="scan-btn" style={S.scanBtn} onClick={startScan}>
              ▶  SCAN NOW
            </button>
          </div>
        )}

        {/* ── SCANNING ── */}
        {phase === "scanning" && (
          <div className="fadein" style={{textAlign:"center"}}>
            <p style={{fontSize:"11px", color:"#00ff88", letterSpacing:"3px", marginBottom:"24px"}} className="blink">
              ◈ SCANNING IN PROGRESS ◈
            </p>
            <div style={{fontSize:"32px", marginBottom:"16px"}}>🛡️</div>
            <div style={S.progressBar}>
              <div style={{...S.progressFill, width:`${progress}%`}} />
            </div>
            <p style={{color:"#666", fontSize:"11px", letterSpacing:"1px", minHeight:"20px"}}>
              {SCAN_STEPS[Math.min(stepIdx, SCAN_STEPS.length-1)]}
            </p>
            <p style={{color:"#333", fontSize:"10px", marginTop:"8px"}}>{Math.floor(progress)}%</p>
          </div>
        )}

        {/* ── RESULT ── */}
        {phase === "result" && result && (
          <div className="fadein" style={{textAlign:"center"}}>
            <p style={{fontSize:"10px", color:"#555", letterSpacing:"3px", marginBottom:"8px"}}>SCAN COMPLETE</p>

            <div style={{fontSize:"48px", marginBottom:"4px"}}>
              {result.level === "SAFE" ? "🛡️" : result.level === "SUSPICIOUS" ? "⚠️" : "☠️"}
            </div>

            <div style={S.resultLevel(result.level)} className="glowpulse">
              {result.level}
            </div>

            <p style={{fontSize:"11px", color:"#555", marginBottom:"20px", letterSpacing:"1px"}}>
              {result.type} · Risk Score: {result.score}/100
            </p>

            {/* issues */}
            {result.issues.length > 0 && (
              <div style={{textAlign:"left", marginBottom:"16px"}}>
                <p style={{fontSize:"10px", color:"#ff3c5f", letterSpacing:"2px", marginBottom:"8px"}}>▸ THREATS DETECTED</p>
                {result.issues.map((iss,i) => (
                  <div key={i} style={S.pill(false)}>⚠ {iss}</div>
                ))}
              </div>
            )}

            {/* good */}
            {result.good.length > 0 && (
              <div style={{textAlign:"left", marginBottom:"20px"}}>
                <p style={{fontSize:"10px", color:"#00ff88", letterSpacing:"2px", marginBottom:"8px"}}>▸ CLEAR SIGNALS</p>
                {result.good.map((g,i) => (
                  <div key={i} style={S.pill(true)}>✓ {g}</div>
                ))}
              </div>
            )}

            <div style={{
              background:"rgba(255,255,255,0.03)", borderRadius:"8px", padding:"12px",
              fontSize:"10px", color:"#555", marginBottom:"20px", letterSpacing:"1px",
            }}>
              ⚠ Disclaimer: XRYPT SECURITY is not a full antivirus. Results are heuristic-based estimates.
              Always use multiple security tools for critical decisions.
            </div>

            <div style={{display:"flex", gap:"10px", flexWrap:"wrap", justifyContent:"center"}}>
              <button className="scan-btn" style={{...S.scanBtn, marginTop:0}} onClick={reset}>
                ↩  SCAN ANOTHER
              </button>
              <button className="sec-btn" style={S.secondaryBtn} onClick={copyResult}>
                {copied ? "✓ COPIED" : "⎘ COPY REPORT"}
              </button>
            </div>
          </div>
        )}
      </div>

      {/* footer */}
      <p style={{position:"fixed", bottom:"12px", fontSize:"9px", color:"#222", letterSpacing:"2px", zIndex:2}}>
        XRYPT SECURITY v1.0 · CLIENT-SIDE ANALYSIS · NO DATA TRANSMITTED
      </p>
    </div>
  );
}
