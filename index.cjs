require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const cors = require("cors");
const sgMail = require("@sendgrid/mail");
const admin = require("firebase-admin");

// ---------------- FIREBASE SERVICE ACCOUNT ----------------
const serviceAccount = {
  type: process.env.FIREBASE_TYPE,
  project_id: process.env.FIREBASE_PROJECT_ID,
  private_key: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, "\n"),
  client_email: process.env.FIREBASE_CLIENT_EMAIL,
};

// Initialize Firebase
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  databaseURL: process.env.FIREBASE_DATABASE_URL,
});

// ---------------- SENDGRID ----------------
sgMail.setApiKey(process.env.SENDGRID_API_KEY);

// ---------------- EXPRESS APP ----------------
const app = express();
app.use(cors());
app.use(bodyParser.json());

const PORT = 5000;

app.get("/", (req, res) => {
  res.send("Myrtle backend is running!");
});

// ---------------- SEND OTP ----------------
app.post("/send-otp", async (req, res) => {
  try {
    const email = req.body.email?.trim();
    if (!email) return res.status(400).json({ message: "Email is required." });

    const otp = Math.floor(100000 + Math.random() * 900000);
    const expiresAt = Date.now() + 5 * 60 * 1000; // 5 mins

    await admin.firestore().doc(`passwordResets/${email}`).set({ otp, expiresAt, attempts: 0 });
    console.log("Saved OTP:", otp, "for", email);

    await sgMail.send({
      to: email,
      from: "no-reply@tamanghula.online", 
      templateId: process.env.SENDGRID_TEMPLATE_ID,
      dynamic_template_data: { otp }
    });

    res.json({ message: "OTP sent successfully" });
  } catch (err) {
    console.log("SEND OTP ERROR:", err);
    res.status(500).json({ message: "Error sending OTP" });
  }
});

// ---------------- VERIFY OTP ----------------
app.post("/verify-otp", async (req, res) => {
  try {
    const email = req.body.email?.trim();
    const otpInput = Number(req.body.otp);

    if (!email || isNaN(otpInput)) return res.status(400).json({ message: "Email and valid OTP required." });

    const docRef = admin.firestore().doc(`passwordResets/${email}`);
    const docSnap = await docRef.get();

    if (!docSnap.exists) return res.status(400).json({ message: "OTP not found." });

    const data = docSnap.data();

    if (Date.now() > data.expiresAt) return res.status(400).json({ message: "OTP expired." });
    if (data.attempts >= 5) return res.status(400).json({ message: "Too many attempts." });

    if (otpInput !== data.otp) {
      await docRef.update({ attempts: data.attempts + 1 });
      return res.status(400).json({ message: "Invalid OTP" });
    }

    res.json({ message: "OTP verified." });
  } catch (err) {
    console.log("VERIFY OTP ERROR:", err);
    res.status(500).json({ message: "Error verifying OTP" });
  }
});

// ---------------- RESET PASSWORD ----------------
app.post("/reset-password", async (req, res) => {
  try {
    const email = req.body.email?.trim();
    const newPassword = req.body.newPassword?.trim();

    if (!email || !newPassword || newPassword.length < 6) {
      return res.status(400).json({ message: "Email and valid password required (min 6 chars)." });
    }

    const userRecord = await admin.auth().getUserByEmail(email);
    await admin.auth().updateUser(userRecord.uid, { password: newPassword });
    await admin.firestore().doc(`passwordResets/${email}`).delete();

    res.json({ message: "Password updated successfully." });
  } catch (err) {
    console.log("RESET PASSWORD ERROR:", err);
    res.status(500).json({ message: "Error resetting password." });
  }
});

// ---------------- START SERVER ----------------
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));