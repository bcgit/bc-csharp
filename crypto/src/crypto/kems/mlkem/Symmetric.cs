using System;

using Org.BouncyCastle.Crypto.Digests;

namespace Org.BouncyCastle.Crypto.Kems.MLKem
{
    internal abstract class Symmetric
    {
        internal readonly int XofBlockBytes;

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        internal abstract void Hash_h(ReadOnlySpan<byte> input, Span<byte> output);

        internal abstract void Hash_g(ReadOnlySpan<byte> input, Span<byte> output);

        internal abstract void Kdf(ReadOnlySpan<byte> input, Span<byte> output);

        internal abstract void Prf(ReadOnlySpan<byte> seed, byte nonce, Span<byte> output);

        internal abstract void XofAbsorb(ReadOnlySpan<byte> seed, byte x, byte y);

        internal abstract void XofSqueezeBlocks(Span<byte> output);
#else
        internal abstract void Hash_h(byte[] inBuf, int inOff, int inLen, byte[] outBuf, int outOff);

        internal abstract void Hash_g(byte[] input, byte[] output);

        internal abstract void Kdf(byte[] input, byte[] output);

        internal abstract void Prf(byte[] seed, byte nonce, byte[] output);

        internal abstract void XofAbsorb(byte[] seed, byte x, byte y);

        internal abstract void XofSqueezeBlocks(byte[] output, int outOffset, int outLen);
#endif

        internal Symmetric(int xofBlockBytes)
        {
            this.XofBlockBytes = xofBlockBytes;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        internal static void DoDigest(IDigest digest, ReadOnlySpan<byte> input, Span<byte> output)
        {
            digest.BlockUpdate(input);
            digest.DoFinal(output);
        }
#else
        internal static void DoDigest(IDigest digest, byte[] inBuf, int inOff, int inLen, byte[] outBuf, int outOff)
        {
            digest.BlockUpdate(inBuf, inOff, inLen);
            digest.DoFinal(outBuf, outOff);
        }
#endif

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

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            internal override void Hash_h(ReadOnlySpan<byte> input, Span<byte> output) =>
                DoDigest(sha3Digest256, input, output);

            internal override void Hash_g(ReadOnlySpan<byte> input, Span<byte> output) =>
                DoDigest(sha3Digest512, input, output);

            internal override void Kdf(ReadOnlySpan<byte> input, Span<byte> output) =>
                DoDigest(shakeDigest, input, output);

            internal override void Prf(ReadOnlySpan<byte> seed, byte nonce, Span<byte> output)
            {
                shakeDigest.BlockUpdate(seed);
                shakeDigest.Update(nonce);
                shakeDigest.OutputFinal(output);
            }

            internal override void XofAbsorb(ReadOnlySpan<byte> seed, byte x, byte y)
            {
                Span<byte> xy = stackalloc byte[2]{ x, y };

                xof.Reset();
                xof.BlockUpdate(seed);
                xof.BlockUpdate(xy);
            }

            internal override void XofSqueezeBlocks(Span<byte> output)
            {
                xof.Output(output);
            }
#else
            internal override void Hash_h(byte[] inBuf, int inOff, int inLen, byte[] outBuf, int outOff) =>
                DoDigest(sha3Digest256, inBuf, inOff, inLen, outBuf, outOff);

            internal override void Hash_g(byte[] input, byte[] output) =>
                DoDigest(sha3Digest512, input, 0, input.Length, output, 0);

            internal override void Kdf(byte[] input, byte[] output) =>
                DoDigest(shakeDigest, input, 0, input.Length, output, 0);

            internal override void Prf(byte[] seed, byte nonce, byte[] output)
            {
                shakeDigest.BlockUpdate(seed, 0, seed.Length);
                shakeDigest.Update(nonce);
                shakeDigest.OutputFinal(output, 0, output.Length);
            }

            internal override void XofAbsorb(byte[] seed, byte x, byte y)
            {
                byte[] xy = new byte[2]{ x, y };

                xof.Reset();
                xof.BlockUpdate(seed, 0, seed.Length);
                xof.BlockUpdate(xy, 0, xy.Length);
            }

            internal override void XofSqueezeBlocks(byte[] output, int outOffset, int outLen)
            {
                xof.Output(output, outOffset, outLen);
            }
#endif
        }
    }
}
