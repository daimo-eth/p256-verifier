import fetch from "cross-fetch";
import fs from "fs";

const sourceURLs = [
  "https://raw.githubusercontent.com/google/wycheproof/master/testvectors/ecdsa_secp256r1_sha256_test.json",
];

async function main() {
  // Download latest Wycheproof vectors
  const vectors = [];
  for (const url of sourceURLs) {
    console.log(`Downloading ${url}`);
    const sourceObj = await fetch(url).then((res) => res.json());
    const vecs = await extractVectors(sourceObj);
    console.log(`Extracted ${vecs.length} vectors`);
    vectors.push(...vecs);
  }

  // Write to JSON
  const filepath = "../test/vectors.jsonl";
  console.log(`Writing ${vectors.length} vectors to ${filepath}`);
  const lines = vectors.map((v) => JSON.stringify(v));
  fs.writeFileSync(filepath, lines.join("\n"));
}

async function extractVectors(sourceObj: any) {
  const vectors = [];
  for (const group of sourceObj.testGroups) {
    const { type, key, sha } = group;
    assert(sha === "SHA-256");

    // Parse key point w
    const x = key.wx.length === 66 ? key.wx.substring(2) : key.wx;
    const y = key.wy.length === 66 ? key.wy.substring(2) : key.wy;
    // if (x.length !== 64 || y.length !== 64) {
    //   console.log(`Skipping bad key ${type} ${sha}: ${JSON.stringify(key)}...`);
    //   continue;
    // }

    for (const test of group.tests) {
      const { tcId, comment, msg, sig, result } = test;
      const testStr = `${type} ${sha} #${tcId}`;

      // Many Wycheproof vectors are not actually testing P256, but rather the
      // ASN decoding. We only want the P256 vectors.
      let r, s;
      try {
        [r, s] = tryParseASN(sig);
      } catch (e: any) {
        console.warn(`Skipping bad sig ${testStr}: ${e.message} ${comment}`);
        continue;
      }

      assert(["valid", "invalid", "acceptable"].includes(result));

      // calculate SHA256 hash of msgBytes
      const msgBytes = Buffer.from(msg, "hex");
      const msgHash = Buffer.from(
        await crypto.subtle.digest("SHA-256", msgBytes)
      );

      vectors.push({
        x,
        y,
        r,
        s,
        hash: msgHash.toString("hex"),
        result,
        comment: `wycheproof ${testStr}: ${comment}`,
      });
    }
  }

  return vectors;
}

// Parse r,s from an ASN-encoded signature
function tryParseASN(sig: string): [string, string] {
  let r, rLen, s, sLen, totalLen;
  let rem = consume(sig, "30"); // SEQUENCE
  [totalLen, rem] = read(rem, 2); // length, verified at the end
  assert(parseInt(totalLen, 16) === sig.length / 2 - 2);

  rem = consume(rem, "02"); // INTEGER
  [rLen, rem] = read(rem, 2);
  if (rLen === "21") rem = consume(rem, "00");
  else assert(rLen === "20");
  [r, rem] = read(rem, 64);

  rem = consume(rem, "02"); // INTEGER
  [sLen, rem] = read(rem, 2);
  if (sLen === "21") rem = consume(rem, "00");
  else assert(sLen === "20");
  [s, rem] = read(rem, 64);
  assert(rem === "");

  return [r, s];
}

function consume(str: string, prefix: string) {
  if (!str.startsWith(prefix)) {
    throw new Error(`exp ${prefix}, found ${str.substring(0, prefix.length)}`);
  }
  return str.substring(prefix.length);
}

function read(str: string, n: number) {
  assert(str.length >= n);
  return [str.substring(0, n), str.substring(n)];
}

function assert(cond: boolean) {
  if (!cond) throw new Error();
}

main()
  .then(() => console.log("Done"))
  .catch((err) => console.error(err));
