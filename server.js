// gen-keys.js
const fs = require("fs");

function randChunk(len) {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  let s = "";
  for (let i = 0; i < len; i++) s += chars[Math.floor(Math.random() * chars.length)];
  return s;
}

const KEYS = [];
for (let i = 1; i <= 1000; i++) {
  const key =
    "UFO-KEY-" +
    randChunk(5) + "-" +
    String(i).padStart(5, "0"); // UFO-KEY-ABCDE-00001 ...
  KEYS.push({
    key,
    ttl: 3600,         // อายุคีย์ 1 ชม. หลัง verify ผ่าน
    reusable: false    // “คีย์ต่อคน” (อยากให้คีย์สาธารณะให้เปลี่ยนเป็น true)
  });
}

const doc = {
  expires_default: 3600,
  keys: KEYS
};

fs.writeFileSync("keys.json", JSON.stringify(doc, null, 2), "utf8");
console.log("[gen-keys] wrote keys.json with", KEYS.length, "keys");
