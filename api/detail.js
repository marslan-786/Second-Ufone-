import crypto from "crypto";
import axios from "axios";

const Sy =
  "dgsd" +
  "354twf" +
  "35esef" +
  "gdsjk543dlkfjdlkdsjklgjkljtkjlj" +
  "v534lklflksdjfd" +
  "gdgdfh" +
  "5463ff" +
  "v534lklflksdjfd" +
  "35esef";

const HOST = "ufone-claim.site";
const API_URL = "https://backend.ufone-claim.site/api/get-user-details";

function generateXCaptchaToken(secretKey) {
  const ts = Date.now().toString();
  const h = crypto.createHmac("sha256", secretKey);
  h.update(ts);
  const sig = h.digest("base64");
  return Buffer.from(ts).toString("base64") + "." + sig;
}

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
  const ct = Buffer.concat([
    cipher.update(JSON.stringify(dataObj)),
    cipher.final(),
  ]);
  const tag = cipher.getAuthTag();

  return Buffer.concat([salt, iv, ct, tag]).toString("base64");
}

export default async function handler(req, res) {
  try {
    // API ONLY ACCEPTS POST
    if (req.method !== "POST") {
      return res.status(405).json({ error: "Use POST request only" });
    }

    const { phone, token, subtoken, id } = req.body || {};

    if (!phone || !token || !subtoken || !id) {
      return res.status(400).json({
        error:
          "Body Required: { phone: '', token: '', subtoken: '', id: '' }",
      });
    }

    const payloadObj = {
      phoneNumber: phone,
      token: token,
      subToken: subtoken,
      deviceId: id,
    };

    const encryptedPayload = encryptPayloadWithHost(HOST, payloadObj);
    const xtoken = generateXCaptchaToken(Sy);

    const headers = {
      "User-Agent":
        "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Mobile Safari/537.36",
      Accept: "*/*",
      "Content-Type": "application/json",
      Origin: `https://${HOST}`,
      Referer: `https://${HOST}/`,
      "X-Captcha-Token": xtoken,
    };

    const apiRes = await axios.post(
      API_URL,
      { payload: encryptedPayload },
      {
        headers,
        responseType: "text",
        validateStatus: () => true,
      }
    );

    res.status(200).json({
      success: true,
      sentPayload: payloadObj,
      rawBackendResponse: apiRes.data,
    });
  } catch (err) {
    res.status(500).json({
      error: err.message,
      raw: err?.response?.data || null,
    });
  }
}
