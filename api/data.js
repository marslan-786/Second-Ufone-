import crypto from "crypto";
import axios from "axios";

// 1. Secret Key Parts (Exactly from index.js)
const Cy = "dgsd";
const Ey = "354twf";
const Ay = "5463ff";
const v0 = "35esef";
const Dy = "gdsjk543dlkfjdlkdsjklgjkljtkjlj";
const y0 = "v534lklflksdjfd";
const By = "gdgdfh";

// Final Secret Key Construction
const Sy = Cy + Ey + v0 + Dy + y0 + By + Ay + y0 + v0;

// 2. Configuration (UPDATED BASED ON YOUR DECRYPTION)
// ✅ آپ کی ٹیسٹنگ کے مطابق، صحیح ہوسٹ یہ ہے:
const MOCKED_HOST = "www.ufone-claim.site"; 

// Real API URL
const API_URL = "https://my-express-api.talhariaz5425869.workers.dev/api/get-all-data";

/**
 * Generate X-Captcha-Token
 */
function generateXCaptchaToken(secretKey) {
  const ts = Date.now().toString();
  const h = crypto.createHmac("sha256", secretKey);
  h.update(ts);
  const sig = h.digest("base64");
  return Buffer.from(ts).toString("base64") + "." + sig;
}

/**
 * Encrypt Payload
 */
function encryptPayloadWithHost(hostString, dataObj) {
  // 1. Generate Salt & IV
  const salt = crypto.randomBytes(16);
  const iv = crypto.randomBytes(12);

  // 2. Derive Key (PBKDF2) - Using "www.ufone-claim.site" as password
  const key = crypto.pbkdf2Sync(
    Buffer.from(hostString, "utf8"),
    salt,
    100000,
    32,
    "sha256"
  );

  // 3. Encrypt (AES-256-GCM)
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  
  const encryptedBuffer = Buffer.concat([
    cipher.update(JSON.stringify(dataObj), "utf8"),
    cipher.final(),
  ]);
  
  // 4. Get Auth Tag
  const tag = cipher.getAuthTag();

  // 5. Combine parts
  return Buffer.concat([salt, iv, encryptedBuffer, tag]).toString("base64");
}

export default async function handler(req, res) {
  try {
    if (req.method !== "POST") {
      return res.status(405).json({ error: "Use POST request only" });
    }

    const { phone, token, subtoken, id } = req.body || {};

    if (!phone || !token || !subtoken || !id) {
      return res.status(400).json({
        error: "Missing required fields: phone, token, subtoken, id",
      });
    }

    const payloadObj = {
      phoneNumber: phone,
      token: token,
      subToken: subtoken,
      deviceId: id,
    };

    // ✅ Encrypt using "www.ufone-claim.site"
    const encryptedPayload = encryptPayloadWithHost(MOCKED_HOST, payloadObj);
    
    // Generate Token
    const xtoken = generateXCaptchaToken(Sy);

    const headers = {
      "User-Agent": "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
      "Accept": "application/json, text/plain, */*",
      "Content-Type": "application/json",
      // ✅ Origin and Referer will now match the encryption host
      "Origin": `https://${MOCKED_HOST}`,
      "Referer": `https://${MOCKED_HOST}/`,
      "X-Captcha-Token": xtoken,
    };

    console.log(`🚀 Requesting data for ${phone}...`);
    console.log(`🔒 Encrypted with Host: ${MOCKED_HOST}`);

    const apiRes = await axios.post(
      API_URL,
      { payload: encryptedPayload },
      {
        headers,
        validateStatus: () => true, 
      }
    );

    // Backend Response Handling
    res.status(apiRes.status).json({
      success: apiRes.data?.success || false,
      backendStatus: apiRes.status,
      data: apiRes.data,
    });

  } catch (err) {
    console.error("❌ API Proxy Error:", err.message);
    res.status(500).json({
      error: err.message,
      stack: process.env.NODE_ENV === 'development' ? err.stack : undefined
    });
  }
}
