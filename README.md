🛡️ Sangyan: Multi-Vector Fraud & Scam Interceptor

Verify before you trust. Sangyan checks a suspicious message, link, screenshot or voice note against real registries, explains the risk in the user's own language, and helps them report it.

**Idea**
Sangyan is a scam interceptor for first-time Indian investors. A user pastes or uploads a suspicious message, link, screenshot or voice note, and finds out within seconds whether it's a scam, and why, before sending any money.

**Approach**
Facts first, AI second. Sangyan extracts indicators (SEBI IDs, UPI IDs, phone numbers, domains) and checks them against a SEBI registry and a threat database. Rule engines then check for fake or stolen registrations, cloned domains, and scam language in English, Hinglish and Hindi. An LLM is called only when the result is uncertain, and it can raise the risk score but never lower it.

**Solution**
The user gets an explainable risk score with a named reason for every signal, and a spoken warning in their own language. If they've already lost money, Sangyan generates a complaint with evidence attached, plus a guide to filing it with 1930, the Cyber Crime portal and SEBI SCORES.

**Innovation**
- **Verifiable checks.** It catches a real SEBI ID being used by the wrong firm, and look-alike domains, which a plain chatbot can't verify.
- **Gated LLM.** AI is used only where rules can't reach, which keeps it cheap, auditable and hard to manipulate.
- **Safe learning.** Its threat database grows with each new case, but unconfirmed indicators stay low-weight until they're corroborated.
- **End-to-end flow.** It covers detection, a local-language explanation and complaint filing in a single tool.

