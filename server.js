// server.js
require('dotenv').config();

const express = require('express');
const cors    = require('cors');
const path    = require('path');
const nodemailer = require('nodemailer');
const crypto  = require('crypto');

const app  = express();
const PORT = process.env.PORT || 5000;

// ─── Middleware ────────────────────────────────────────────────────────────────
app.use(cors({ origin: process.env.CLIENT_URL || '*' }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ─── Config ───────────────────────────────────────────────────────────────────
const OTP_LENGTH             = parseInt(process.env.OTP_LENGTH          || '6',  10);
const OTP_EXPIRY_MINUTES     = parseInt(process.env.OTP_EXPIRY_MINUTES  || '5',  10);
const MAX_ATTEMPTS           = parseInt(process.env.MAX_ATTEMPTS         || '5',  10);
const RESEND_COOLDOWN_SECONDS = parseInt(process.env.RESEND_COOLDOWN     || '60', 10);

// ─── In-Memory OTP Store ──────────────────────────────────────────────────────
// Shape: email → { otpHash, expiresAt, attempts, lastSentAt }
// For production replace with Redis (SET key value EX ttl) or a DB table.
const otpStore = new Map();

// ─── Mailer ───────────────────────────────────────────────────────────────────
const transporter = nodemailer.createTransport({
  host:   process.env.SMTP_HOST,
  port:   parseInt(process.env.SMTP_PORT || '465', 10),
  secure: process.env.SMTP_SECURE !== 'false', // true by default (port 465)
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
});

// ─── Helpers ──────────────────────────────────────────────────────────────────

/** Cryptographically random numeric OTP */
function generateOTP(length = OTP_LENGTH) {
  let otp = '';
  for (let i = 0; i < length; i++) {
    otp += crypto.randomInt(0, 10).toString();
  }
  return otp;
}

/** SHA-256 hash — never store a plain OTP */
function hashOTP(otp) {
  return crypto.createHash('sha256').update(String(otp).trim()).digest('hex');
}

/** Minimal email format check */
function isValidEmail(email) {
  return typeof email === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim());
}

/** Send the OTP email */
async function sendOTPEmail(toEmail, otp) {
  await transporter.sendMail({
    from:    process.env.EMAIL_FROM || process.env.SMTP_USER,
    to:      toEmail,
    subject: 'Your verification code',
    text:    `Your code is ${otp}. It expires in ${OTP_EXPIRY_MINUTES} minutes. Do not share it.`,
    html: `
      <div style="font-family:system-ui,Arial,sans-serif;max-width:480px;margin:0 auto;
                  padding:32px 24px;border:1px solid #e2e8f0;border-radius:12px;background:#fff;">
        <h2 style="margin:0 0 8px;color:#0f172a;font-size:20px;">Verify your email</h2>
        <p style="margin:0 0 24px;color:#475569;font-size:14px;line-height:1.6;">
          Enter the code below to complete verification.
          It expires in <strong>${OTP_EXPIRY_MINUTES} minutes</strong>.
        </p>
        <div style="display:flex;justify-content:center;margin:0 0 28px;">
          <span style="font-size:36px;font-weight:700;letter-spacing:12px;
                       color:#0f172a;background:#f1f5f9;padding:16px 24px;
                       border-radius:8px;display:inline-block;font-family:monospace;">
            ${otp}
          </span>
        </div>
        <p style="margin:0;color:#94a3b8;font-size:12px;">
          If you didn't request this, you can ignore this email — your account is safe.
        </p>
      </div>`,
  });
}

// ─── Routes ───────────────────────────────────────────────────────────────────

/**
 * POST /api/send-otp
 * Body: { email }
 */
app.post('/api/send-otp', async (req, res) => {
  try {
    const { email } = req.body;

    if (!isValidEmail(email)) {
      return res.status(400).json({ success: false, message: 'A valid email address is required.' });
    }

    const key      = email.trim().toLowerCase();
    const existing = otpStore.get(key);

    // Resend cooldown
    if (existing?.lastSentAt) {
      const elapsed   = Date.now() - existing.lastSentAt;
      const cooldownMs = RESEND_COOLDOWN_SECONDS * 1000;
      if (elapsed < cooldownMs) {
        const waitSec = Math.ceil((cooldownMs - elapsed) / 1000);
        return res.status(429).json({
          success: false,
          message: `Please wait ${waitSec}s before requesting another code.`,
        });
      }
    }

    const otp       = generateOTP();
    const otpHash   = hashOTP(otp);
    const expiresAt = Date.now() + OTP_EXPIRY_MINUTES * 60 * 1000;

    otpStore.set(key, { otpHash, expiresAt, attempts: 0, lastSentAt: Date.now() });

    await sendOTPEmail(key, otp);

    return res.json({
      success: true,
      message: `Verification code sent to ${key}. It expires in ${OTP_EXPIRY_MINUTES} minutes.`,
    });
  } catch (err) {
    console.error('[send-otp]', err);
    return res.status(500).json({ success: false, message: 'Failed to send code. Please try again.' });
  }
});

/**
 * POST /api/verify-otp
 * Body: { email, otp }
 */
app.post('/api/verify-otp', (req, res) => {
  try {
    const { email, otp } = req.body;

    if (!email || !otp) {
      return res.status(400).json({ success: false, message: 'Email and code are required.' });
    }

    const key    = email.trim().toLowerCase();
    const record = otpStore.get(key);

    if (!record) {
      return res.status(400).json({
        success: false,
        message: 'No pending verification found. Please request a new code.',
      });
    }

    if (Date.now() > record.expiresAt) {
      otpStore.delete(key);
      return res.status(400).json({ success: false, message: 'Code has expired. Please request a new one.' });
    }

    if (record.attempts >= MAX_ATTEMPTS) {
      otpStore.delete(key);
      return res.status(429).json({
        success: false,
        message: 'Too many incorrect attempts. Please request a new code.',
      });
    }

    if (hashOTP(otp) !== record.otpHash) {
      record.attempts += 1;
      const remaining = MAX_ATTEMPTS - record.attempts;
      return res.status(400).json({
        success: false,
        message: remaining > 0
          ? `Incorrect code. ${remaining} attempt${remaining === 1 ? '' : 's'} remaining.`
          : 'Too many incorrect attempts. Please request a new code.',
      });
    }

    // ✓ Verified
    otpStore.delete(key);
    return res.json({ success: true, message: 'Email verified successfully!' });
  } catch (err) {
    console.error('[verify-otp]', err);
    return res.status(500).json({ success: false, message: 'Something went wrong. Please try again.' });
  }
});

/** Health check */
app.get('/api/health', (_req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

/** Serve frontend for all other GET routes */
app.get('*', (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ─── Periodic Cleanup (expired OTPs) ─────────────────────────────────────────
setInterval(() => {
  const now = Date.now();
  for (const [key, record] of otpStore.entries()) {
    if (now > record.expiresAt) otpStore.delete(key);
  }
}, 5 * 60 * 1000);

// ─── Start ────────────────────────────────────────────────────────────────────
app.listen(PORT, () => console.log(`Server running → http://localhost:${PORT}`));
