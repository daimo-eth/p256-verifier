import fetch from "cross-fetch";
import fs from "fs";
import { base64urlnopad } from "@scure/base";

const scureVectorsURL =
  "https://github.com/paulmillr/scure-base/raw/main/test/vectors/base_vectors.json";

type ScureVector = {
  fn_name: string;
  data: string;
  exp: string;
};

// Fetch scure's test vectors and filter out base64url
async function main() {
  const sourceObj: { v: ScureVector[] } = await fetch(scureVectorsURL).then(
    (res) => res.json()
  );
  const vectors = sourceObj.v.filter(
    (v: ScureVector) => v.fn_name === "base64url"
  );

  // Write to JSON
  const filepath = "./vectors_scure_base64url.jsonl";
  console.log(`Writing ${vectors.length} vectors to ${filepath}`);
  const lines = vectors.map((v) => {
    const data = Uint8Array.from(Buffer.from(v.data, "hex"));
    return JSON.stringify({
      data: `0x${v.data}`,
      base64url: base64urlnopad.encode(data),
    });
  });
  fs.writeFileSync(filepath, lines.join("\n"));
}

main()
  .then(() => console.log("Done"))
  .catch((err) => console.error(err));
