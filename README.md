# Intelligent-Traffic-Filtering-Firewall-Engine

## Firewall Rules Simulator (Beginner-friendly)

**Purpose**
- Small, easy-to-understand demo that shows how firewall rules (priority, allow/deny, direction) work at an application level.
- Safe learning project — **not** a real network/OS firewall.

**How it works (short)**
- Rules and lists live in a single `firewallConfig` object.
- Rules have a `priority` number; lower = higher precedence. First matching rule wins.
- Supports explicit `ALLOW` and `DENY`, direction (`INBOUND`), and simple logging.
- Implemented as Express middleware so **every** HTTP request is checked before routes run.

**Quick start**
1. Install dependencies: `npm install express dotenv morgan express-rate-limit`
2. Create a `.env` file (example provided) or use defaults. Values available: `PORT`, `RATE_LIMIT_WINDOW` (minutes), `RATE_LIMIT_MAX_REQUESTS`.
3. Run the demo server: `node server.js`
4. Try these in browser or Postman:
   - `GET http://localhost:3000/public`  — should be allowed
   - `GET http://localhost:3000/admin`   — should be blocked (example)
   - `POST http://localhost:3000/data`   — allowed only from localhost (demo rule)
   - `GET http://localhost:3000/check-traffic?ip=127.0.0.1&port=80&protocol=TCP` — simulate
   - `GET http://localhost:3000/firewall-log` — view recent decisions

**Notes about env and security**
- `dotenv` allows using environment variables for configuration (safer than hardcoding). Keep secrets out of source control.
- `morgan` logs requests to help with auditing; `express-rate-limit` provides basic DoS protection by limiting requests.


**Core concepts to mention (interview-ready)**
- Rule priority and first-match vs highest-priority semantics
- Explicit `DENY` should override `ALLOW` when prioritized
- Default-deny (least privilege) — block when no rule matches
- Middleware enforces policies at the application layer (Layer 7)
- This project demonstrates design, not packet processing or kernel hooks

**Sample interview questions (short answers)**
- Q: Why not implement a real firewall? A: Kernel-level access, privileges, safety, and complexity — out of scope for a beginner project.
- Q: What does default-deny mean? A: If no rule matches, deny by default (least privilege).
- Q: How does priority work here? A: Rules sorted by `priority`; first matching rule decides.
- Q: What is a WAF vs OS firewall? A: WAF = app-layer (HTTP/HTTPS); OS firewall = packet-level, kernel/hardware.

**Notes & limitations**
- In-memory logs (no persistence), simple string/prefix matching, no rate-limiting or IDS/IPS features.
- Good for learning system design and explaining trade-offs.

---
Happy learning — keep the code simple and explain design choices clearly in interviews.