"use client";
import { Prism as SyntaxHighlighter } from "react-syntax-highlighter";

import Image from "next/image";
import { useEffect, useState } from "react";
import toast, { Toaster } from "react-hot-toast";
import { oneLight } from "react-syntax-highlighter/dist/esm/styles/prism";
import deployments from "./deployments.json";

enum DetailViewOptions {
  Deployments,
  Usage,
}

const signatureTypes = [
  "Secure Enclave",
  "WebAuthn",
  "Passkey",
  "YubiKey",
  "FIDO",
  "Android Keystore",
];

function Title() {
  const address = "0xc2b78104907F722DABAc4C69f826a522B2754De4";

  const copyAddressToClipboard = () => {
    console.log("copying address to clipboard");
    navigator.clipboard.writeText(address);
    toast.success("Copied!");
  };

  return (
    <div className="max-w-5/6 items-center justify-center font-mono lg:text-2xl md:text-md text-xs lg:flex">
      <p className="flex w-full justify-center border-b border-gray-300 static w-auto rounded-xl border bg-gray-200 p-4">
        <code className="font-mono font-bold">P256Verifier:</code>&nbsp;
        {address}&nbsp;
        <button type="button" onClick={copyAddressToClipboard}>
          <div>
            <svg
              className="w-5 h-5"
              fill="none"
              strokeWidth="1.5"
              viewBox="0 0 24 24"
              color="#000000"
            >
              <path
                stroke="#000000"
                strokeWidth="1.5"
                strokeLinecap="round"
                strokeLinejoin="round"
                d="M19.4 20H9.6a.6.6 0 0 1-.6-.6V9.6a.6.6 0 0 1 .6-.6h9.8a.6.6 0 0 1 .6.6v9.8a.6.6 0 0 1-.6.6Z"
              ></path>
              <path
                stroke="#000000"
                strokeWidth="1.5"
                strokeLinecap="round"
                strokeLinejoin="round"
                d="M15 9V4.6a.6.6 0 0 0-.6-.6H4.6a.6.6 0 0 0-.6.6v9.8a.6.6 0 0 0 .6.6H9"
              ></path>
            </svg>
            <span className="sr-only">Copy</span>
          </div>
        </button>
      </p>
      <Toaster position="top-center" />
    </div>
  );
}

function SubTitle() {
  const [signatureType, setSignatureType] = useState<string>(signatureTypes[0]);

  useEffect(() => {
    // randomly change signature type every 3 seconds
    const interval = setInterval(() => {
      const randomIndex = Math.floor(Math.random() * signatureTypes.length);
      setSignatureType(signatureTypes[randomIndex]);
    }, 3000);

    return () => clearInterval(interval);
  });

  return (
    <div className="m-12 items-center justify-center font-mono lg:text-2xl text-md lg:flex">
      <p className="flex w-full justify-center p-4">
        Verify <span className="font-bold">&nbsp;{signatureType}&nbsp;</span>
        signatures on-chain.
      </p>
    </div>
  );
}

function ButtonsBar({
  toggleDetailView,
}: {
  toggleDetailView: (view: DetailViewOptions) => void;
}) {
  return (
    <div className="justify-center items-center my-12 grid text-center lg:max-w-1/2 lg:grid-cols-3">
      <button
        className="mx-6 group rounded-lg border px-5 py-4 transition-colors border-gray-300 hover:bg-gray-100"
        onClick={() => {
          toggleDetailView(DetailViewOptions.Deployments);
        }}
      >
        <h2 className={`mb-3 text-2xl font-semibold`}>
          Deployments{" "}
          <span className="inline-block transition-transform group-hover:translate-x-1 motion-reduce:transform-none">
            &darr;
          </span>
        </h2>
        <p className={`m-0 max-w-[30ch] text-sm opacity-50`}>
          Find on-chain deployments.
        </p>
      </button>

      <button
        className="mx-6 group rounded-lg border px-5 py-4 transition-colors border-gray-300 hover:bg-gray-100"
        onClick={() => {
          toggleDetailView(DetailViewOptions.Usage);
        }}
      >
        <h2 className={`mb-3 text-2xl font-semibold`}>
          Usage{" "}
          <span className="inline-block transition-transform group-hover:translate-x-1 motion-reduce:transform-none">
            &darr;
          </span>
        </h2>
        <p className={`m-0 max-w-[30ch] text-sm opacity-50`}>
          See Solidity usage code.
        </p>
      </button>

      <a
        href="https://vercel.com/templates?framework=next.js&utm_source=create-next-app&utm_medium=appdir-template&utm_campaign=create-next-app"
        className="mx-6 group rounded-lg border px-5 py-4 transition-colors border-gray-300 hover:bg-gray-100"
        target="_blank"
        rel="noopener noreferrer"
      >
        <h2 className={`mb-3 text-2xl font-semibold`}>
          Blog{" "}
          <span className="inline-block transition-transform group-hover:translate-x-1 motion-reduce:transform-none">
            -&gt;
          </span>
        </h2>
        <p className={`m-0 max-w-[30ch] text-sm opacity-50`}>Learn more.</p>
      </a>
    </div>
  );
}

function UsageTab() {
  const usageCode = `bytes32 hash; // message hash
uint256 r, s; // signature
uint256 x, y; // public key

address verifier = 0xc2b78104907F722DABAc4C69f826a522B2754De4;
bytes memory args = abi.encode(hash, r, s, x, y);
(bool success, bytes memory ret) = verifier.staticcall(args);
assert(success); // never reverts, always returns 0 or 1
bool valid = abi.decode(ret, (uint256)) == 1;`;

  return (
    <div className="flex flex-col items-center justify-center">
      <h1 className="text-xl font-bold m-4">Solidity Code</h1>
      <SyntaxHighlighter language="solidity" style={oneLight}>
        {usageCode}
      </SyntaxHighlighter>

      <pre>
        <code></code>
      </pre>
    </div>
  );
}

type Deployment = {
  network: string;
  address: string;
  type: string;
  gas: string;
};

function DeploymentRow(deployment: Deployment) {
  return (
    <tr className="border-black bg-neutral-100">
      <td className="border-black border px-4 py-2">{deployment.network}</td>
      <td className="border-black border px-4 py-2">{deployment.address}</td>
      <td className="border-black border px-4 py-2">{deployment.type}</td>
      <td className="border-black border px-4 py-2">{deployment.gas}</td>
    </tr>
  );
}

function DeploymentsTable() {
  const deploymentRows = deployments as Deployment[];

  return (
    <table className="border-black border min-w-full text-left text-sm font-light">
      <thead className="border-black border bg-neutral-200 font-medium">
        <tr>
          <th className="border-black border px-4 py-2">Network</th>
          <th className="border-black border px-4 py-2">Address</th>
          <th className="border-black border px-4 py-2">Type</th>
          <th className="border-black border px-4 py-2">Gas cost</th>
        </tr>
      </thead>
      <tbody>
        {deploymentRows.map((deployment) => (
          <DeploymentRow key={deployment.network} {...deployment} />
        ))}
      </tbody>
    </table>
  );
}

function DeploymentsTab() {
  return (
    <div className="flex flex-col items-center justify-center">
      <h1 className="text-xl font-bold m-4">Deployments</h1>
      <DeploymentsTable />
    </div>
  );
}

function Footer() {
  return (
    <footer className="flex items-center justify-center w-full">
      <a
        className="m-12 flex items-center justify-center"
        href="https://github.com/daimo-eth/p256-verifier"
        target="_blank"
        rel="noopener noreferrer"
      >
        <Image
          priority
          src="/github-mark.svg"
          height={48}
          width={48}
          alt="GitHub"
        />
      </a>
    </footer>
  );
}

export default function Home() {
  const [detailView, setDetailView] = useState<DetailViewOptions | undefined>(
    undefined
  );

  const toggleDetailView = (view: DetailViewOptions) => {
    if (detailView == view) {
      setDetailView(undefined);
    } else {
      setDetailView(view);
    }
  };

  return (
    <main className="flex flex-col items-center justify-center py-20">
      <Title />
      <SubTitle />
      <ButtonsBar toggleDetailView={toggleDetailView} />
      {detailView == DetailViewOptions.Deployments && <DeploymentsTab />}
      {detailView == DetailViewOptions.Usage && <UsageTab />}
      <Footer />
    </main>
  );
}
