import { writeFile } from "node:fs/promises";

export async function generateKeyPair(outputDir: string): Promise<{
  publicKeyPath: string;
  privateKeyPath: string;
}> {
  const ed = await import("@noble/ed25519");
  const privateKey = ed.utils.randomPrivateKey();
  const publicKey = await ed.getPublicKeyAsync(privateKey);

  const privateKeyPath = `${outputDir}/gateway.key`;
  const publicKeyPath = `${outputDir}/gateway.pub`;

  await writeFile(privateKeyPath, Buffer.from(privateKey), { mode: 0o600 });
  await writeFile(publicKeyPath, Buffer.from(publicKey), { mode: 0o644 });

  return { publicKeyPath, privateKeyPath };
}
