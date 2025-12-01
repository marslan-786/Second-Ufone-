import { NextResponse } from 'next/server';
import crypto from "crypto";
import axios from "axios";

// 1. Secret Key Construction
const Cy = "dgsd";
const Ey = "354twf";
const Ay = "5463ff";
const v0 = "35esef";
const Dy = "gdsjk543dlkfjdlkdsjklgjkljtkjlj";
const y0 = "v534lklflksdjfd";
const By = "gdgdfh";
const Sy = Cy + Ey + v0 + Dy + y0 + By + Ay + y0 + v0;

// 2. Encryption Configuration
const MOCKED_HOST = "www.ufone-claim.site"; 
const BASE_URL = "https://my-express-api.talhariaz5425869.workers.dev";

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
  const salt = crypto.randomBytes(16);
  const iv = crypto.randomBytes(12);

  const key = crypto.pbkdf2Sync(
    Buffer.from(hostString, "utf8"),
    salt,
    100000,
    32,
    "sha256"
  );

  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const encryptedBuffer = Buffer.concat([
    cipher.update(JSON.stringify(dataObj), "utf8"),
    cipher.final(),
  ]);
  const tag = cipher.getAuthTag();

  return Buffer.concat([salt, iv, encryptedBuffer, tag]).toString("base64");
}

export async function POST(req) {
  try {
    const body = await req.json();
    const { phone, token, subToken, deviceId, type, reward } = body;

    // Basic Validation
    if (!phone || !token || !subToken || !deviceId || !type) {
      return NextResponse.json({ 
        error: "Missing fields. Required: phone, token, subToken, deviceId, type, reward{}" 
      }, { status: 400 });
    }

    // 1. Base Payload (Common fields for everyone)
    let payloadObj = {
      phoneNumber: phone,
      token: token,
      subToken: subToken,
      deviceId: deviceId,
    };

    let targetEndpoint = "";

    // 2. Type-Specific Logic (Filling Empty/Default Fields)
    if (type === 'daily') {
        // --- DAILY REWARD LOGIC ---
        // Decrypted log showed: { apId: '', day: '1', dayIdentifier: '1', value: '...' }
        
        targetEndpoint = `${BASE_URL}/api/claim-daily-reward`;
        
        payloadObj = {
            ...payloadObj,
            // ✅ IMPORTANT: Sending empty strings to match original request exactly
            apId: "", 
            day: reward.day || "",
            dayIdentifier: reward.dayIdentifier || reward.day || "",
            value: reward.value || ""
        };

    } else if (type === 'spin') {
        // --- SPIN REWARD LOGIC ---
        // Decrypted log showed: { apId: '...', incentiveValue: '...', bulkClaim: false }
        
        targetEndpoint = `${BASE_URL}/api/claim-reward`;

        payloadObj = {
            ...payloadObj,
            apId: reward.apId || "",
            incentiveValue: reward.incentiveValue || "",
            value: reward.value || "",
            // ✅ IMPORTANT: Sending bulkClaim as false (as seen in decrypted logs)
            bulkClaim: false 
        };
    } else {
        return NextResponse.json({ error: "Invalid type. Use 'spin' or 'daily'" }, { status: 400 });
    }

    // 3. Encrypt the Constructed Payload
    const encryptedPayload = encryptPayloadWithHost(MOCKED_HOST, payloadObj);
    const xtoken = generateXCaptchaToken(Sy);

    // 4. Headers
    const headers = {
      "User-Agent": "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
      "Accept": "application/json, text/plain, */*",
      "Content-Type": "application/json",
      "Origin": `https://${MOCKED_HOST}`,
      "Referer": `https://${MOCKED_HOST}/`,
      "X-Captcha-Token": xtoken,
    };

    console.log(`🚀 Claiming ${type} reward for ${phone}...`);
    console.log(`📦 Payload Keys:`, Object.keys(payloadObj)); // Debugging payload keys

    // 5. Send Request
    const apiRes = await axios.post(
      targetEndpoint,
      { payload: encryptedPayload },
      {
        headers,
        validateStatus: () => true, 
      }
    );

    // 6. Return Response
    return NextResponse.json({
      success: apiRes.data?.success || false,
      backendStatus: apiRes.status,
      type: type,
      responseDesc: apiRes.data?.responseDesc || apiRes.data?.message, // Common response messages
      data: apiRes.data,
    });

  } catch (err) {
    console.error("❌ Claim API Error:", err.message);
    return NextResponse.json({ error: err.message }, { status: 500 });
  }
}
