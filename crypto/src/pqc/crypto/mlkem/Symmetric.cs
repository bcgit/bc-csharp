using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;

namespace Org.BouncyCastle.Pqc.Crypto.MLKem
{
    internal abstract class Symmetric
    {
        internal readonly int XofBlockBytes;

        internal abstract void Hash_h(byte[] output, byte[] input, int outOffset);

        internal abstract void Hash_g(byte[] output, byte[] input);

        internal abstract void XofAbsorb(byte[] seed, byte x, byte y);

        internal abstract void XofSqueezeBlocks(byte[] output, int outOffset, int outLen);

        internal abstract void Prf(byte[] output, byte[] key, byte nonce);

        internal abstract void Kdf(byte[] output, byte[] input);

        internal Symmetric(int xofBlockBytes)
        {
            this.XofBlockBytes = xofBlockBytes;
        }

        internal static void DoDigest(IDigest digest, byte[] output, byte[] input, int outOffset)
        {
            digest.BlockUpdate(input, 0, input.Length);
            digest.DoFinal(output, outOffset);
        }

        internal sealed class ShakeSymmetric
            : Symmetric
        {
            private readonly ShakeDigest xof;
            private readonly Sha3Digest sha3Digest512;
            private readonly Sha3Digest sha3Digest256;
            private readonly ShakeDigest shakeDigest;

            internal ShakeSymmetric()
                : base(164)
            {
                xof = new ShakeDigest(128);
                shakeDigest = new ShakeDigest(256);
                sha3Digest256 = new Sha3Digest(256);
                sha3Digest512 = new Sha3Digest(512);
            }

            internal override void Hash_h(byte[] output, byte[] input, int outOffset) =>
                DoDigest(sha3Digest256, output, input, outOffset);

            internal override void Hash_g(byte[] output, byte[] input) =>
                DoDigest(sha3Digest512, output, input, 0);

            internal override void XofAbsorb(byte[] seed, byte x, byte y)
            {
                xof.Reset();
                byte[] buf = new byte[seed.Length + 2];
                Array.Copy(seed, 0, buf, 0, seed.Length);
                buf[seed.Length] = x;
                buf[seed.Length + 1] = y;
                xof.BlockUpdate(buf, 0, seed.Length + 2);
            }

            internal override void XofSqueezeBlocks(byte[] output, int outOffset, int outLen)
            {
                xof.Output(output, outOffset, outLen);
            }

            internal override void Prf(byte[] output, byte[] seed, byte nonce)
            {
                byte[] extSeed = new byte[seed.Length + 1];
                Array.Copy(seed, 0, extSeed, 0, seed.Length);
                extSeed[seed.Length] = nonce;
                shakeDigest.BlockUpdate(extSeed, 0, extSeed.Length);
                shakeDigest.OutputFinal(output, 0, output.Length);
            }

            internal override void Kdf(byte[] output, byte[] input) =>
                DoDigest(shakeDigest, output, input, 0);
        }
    }
}
