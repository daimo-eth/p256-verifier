import fs from "fs";

interface Vector {
  x: string;
  y: string;
  r: string;
  s: string;
  hash: string;
  result: "valid" | "invalid" | "acceptable";
  comment: string;
}

// Validate generated vectors using the known-good SubtleCrypto P256 verifier.
// We then use the vectors to test other implementations like P256Verifier.sol
async function main() {
  const vectorsJSONL = fs.readFileSync("../test/vectors.jsonl", "utf8");
  const vectors = vectorsJSONL
    .split("\n")
    .map((line) => JSON.parse(line) as Vector);

  for (const vector of vectors) {
    // Convert hex strings to Uint8Arrays
    const x = Buffer.from(vector.x, "hex");
    const y = Buffer.from(vector.y, "hex");
    const r = Buffer.from(vector.r, "hex");
    const s = Buffer.from(vector.s, "hex");
    const hash = Buffer.from(vector.hash, "hex");

    // Validate using SubtleCrypto
    const key = await crypto.subtle.importKey(
      "jwk",
      { kty: "EC", crv: "P-256", x, y },
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"]
    );
    const valid = await crypto.subtle.verify(
      { name: "ECDSA", hash },
      key,
      Buffer.concat([r, s]),
      hash
    );
  }
}

main()
  .then(() => console.log("Done"))
  .catch(console.error);
