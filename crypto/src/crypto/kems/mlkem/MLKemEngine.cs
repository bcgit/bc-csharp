using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;

using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Kems.MLKem
{
    internal sealed class MLKemEngine
    {
        private readonly IndCpa m_indCpa;

        // Constant Parameters
        internal const int N = 256;
        internal const int Q = 3329;
        internal const int QInv = 62209;

        internal const int SymBytes = 32;
        internal const int SharedSecretBytes = 32;

        internal const int PolyBytes = 384;

        internal const int Eta2 = 2;

        internal const int SeedBytes = SymBytes * 2;

        // Parameters
        internal int K { get; private set; }
        internal int PolyVecBytes { get; private set; }
        internal int PolyCompressedBytes { get; private set; }
        internal int PolyVecCompressedBytes { get; private set; }
        internal int Eta1 { get; private set; }
        internal int IndCpaPublicKeyBytes { get; private set; }
        internal int IndCpaSecretKeyBytes { get; private set; }
        internal int PublicKeyBytes => IndCpaPublicKeyBytes;
        internal int SecretKeyBytes { get; private set; }
        internal int CipherTextBytes { get; private set; }

        internal MLKemEngine(int k)
        {
            K = k;
            switch (k)
            {
            case 2:
                Eta1 = 3;
                PolyCompressedBytes = 128;
                PolyVecCompressedBytes = K * 320;
                break;
            case 3:
                Eta1 = 2;
                PolyCompressedBytes = 128;
                PolyVecCompressedBytes = K * 320;
                break;
            case 4:
                Eta1 = 2;
                PolyCompressedBytes = 160;
                PolyVecCompressedBytes = K * 352;
                break;
            default:
                throw new ArgumentException("K: " + k + " is not supported for ML-KEM", nameof(k));
            }

            PolyVecBytes = k * PolyBytes;
            IndCpaPublicKeyBytes = PolyVecBytes + SymBytes;
            IndCpaSecretKeyBytes = PolyVecBytes;
            CipherTextBytes = PolyVecCompressedBytes + PolyCompressedBytes;
            SecretKeyBytes = IndCpaSecretKeyBytes + IndCpaPublicKeyBytes + 2 * SymBytes;

            m_indCpa = new IndCpa(this);
        }

        internal bool CheckDecapKeyHash(byte[] decapKey)
        {
            int k = K, k384 = k * 384, k768 = k * 768;

            byte[] kH = new byte[SymBytes];
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            H(decapKey.AsSpan(k384, k384 + 32), kH.AsSpan());
#else
            H(decapKey, k384, k384 + 32, kH, 0);
#endif

            return Arrays.FixedTimeEquals(SymBytes, kH, 0, decapKey, k768 + 32);
        }

        internal bool CheckEncapKeyModulus(byte[] encapKey) => PolyVec.CheckModulus(this, t: encapKey) < 0;

        internal byte[] CopyEncapKey(byte[] decapKey) =>
            Arrays.CopySegment(decapKey, IndCpaSecretKeyBytes, PublicKeyBytes);

        internal void GenerateKemKeyPair(SecureRandom random, out byte[] seed, out byte[] encoding)
        {
            seed = SecureRandom.GetNextBytes(random, SymBytes * 2);

            GenerateKemKeyPairInternal(seed, out encoding);
        }

        internal void GenerateKemKeyPairInternal(byte[] seed, out byte[] encoding)
        {
            Debug.Assert(seed.Length == SeedBytes);

            encoding = new byte[SecretKeyBytes];

            m_indCpa.GenerateKeyPair(seed, encoding);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            H(encoding.AsSpan(IndCpaSecretKeyBytes, IndCpaPublicKeyBytes),
                encoding.AsSpan(SecretKeyBytes - SymBytes * 2));
#else
            H(encoding, IndCpaSecretKeyBytes, IndCpaPublicKeyBytes, encoding, SecretKeyBytes - SymBytes * 2);
#endif

            Array.Copy(seed, SymBytes, encoding, SecretKeyBytes - SymBytes, SymBytes);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        internal static void G(ReadOnlySpan<byte> input, Span<byte> output) =>
            ImplDigest(new Sha3Digest(512), input, output);

        private static void H(ReadOnlySpan<byte> input, Span<byte> output) =>
            ImplDigest(new Sha3Digest(256), input, output);

        private static void ImplDigest(Sha3Digest digest, ReadOnlySpan<byte> input, Span<byte> output)
        {
            digest.BlockUpdate(input);
            digest.DoFinal(output);
        }

        internal void KemDecrypt(ReadOnlySpan<byte> decapKey, ReadOnlySpan<byte> encapsulation, Span<byte> secret)
        {
            Debug.Assert(decapKey.Length == SecretKeyBytes);

            // TODO Input validation?
            Span<byte> buf = stackalloc byte[2 * SymBytes];
            m_indCpa.Decrypt(encapsulation, decapKey, buf);
            decapKey.Slice(SecretKeyBytes - 2 * SymBytes, SymBytes).CopyTo(buf[SymBytes..]);

            Span<byte> kr = stackalloc byte[2 * SymBytes];
            G(buf, kr);

            Span<byte> cmp = stackalloc byte[CipherTextBytes];
            ReadOnlySpan<byte> pk = decapKey.Slice(IndCpaSecretKeyBytes, IndCpaPublicKeyBytes);

            m_indCpa.Encrypt(pk, buf[..SymBytes], kr[SymBytes..], cmp);

            int fail = ~FixedTimeEquals(cmp, encapsulation);

            // if ciphertexts do not match, “implicitly reject”
            {
                Span<byte> implicitRejection = stackalloc byte[SharedSecretBytes];

                // J(z||c)
                var xof = new ShakeDigest(256);
                xof.BlockUpdate(decapKey.Slice(SecretKeyBytes - SymBytes, SymBytes));
                xof.BlockUpdate(encapsulation);
                xof.OutputFinal(implicitRejection);

                CMov(kr, implicitRejection, SharedSecretBytes, fail);
            }

            kr[..SharedSecretBytes].CopyTo(secret);
        }
 
        internal void KemEncrypt(ReadOnlySpan<byte> encapKey, ReadOnlySpan<byte> randBytes, Span<byte> encapsulation,
            Span<byte> secret)
        {
            Debug.Assert(encapKey.Length == PublicKeyBytes);
            Debug.Assert(randBytes.Length == SymBytes);

            Span<byte> buf = stackalloc byte[2 * SymBytes];
            Span<byte> kr = stackalloc byte[2 * SymBytes];

            randBytes[..SymBytes].CopyTo(buf);

            H(encapKey, buf[SymBytes..]);

            G(buf, kr);

            m_indCpa.Encrypt(encapKey, buf[..SymBytes], kr[SymBytes..], encapsulation);

            kr[..SharedSecretBytes].CopyTo(secret);
        }

        [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
        private static void CMov(Span<byte> r, ReadOnlySpan<byte> x, int xLen, int cond)
        {
            Debug.Assert(0 == cond || -1 == cond);

            for (int i = 0; i < xLen; ++i)
            {
                int r_i = r[i], diff = r_i ^ x[i];
                r_i ^= diff & cond;
                r[i] = (byte)r_i;
            }
        }

        [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
        public static int FixedTimeEquals(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
        {
            int d = 0;
            for (int i = 0, len = a.Length; i < len; ++i)
            {
                d |= a[i] ^ b[i];
            }
            d |= d >> 16;
            d &= 0xFFFF;
            return (d - 1) >> 31;
        }
#else
        internal static void G(byte[] input, byte[] output) =>
            ImplDigest(new Sha3Digest(512), input, 0, input.Length, output, 0);

        private static void H(byte[] inBuf, int inOff, int inLen, byte[] outBuf, int outOff) =>
            ImplDigest(new Sha3Digest(256), inBuf, inOff, inLen, outBuf, outOff);

        private static void ImplDigest(Sha3Digest digest, byte[] inBuf, int inOff, int inLen, byte[] outBuf, int outOff)
        {
            digest.BlockUpdate(inBuf, inOff, inLen);
            digest.DoFinal(outBuf, outOff);
        }

        internal void KemDecrypt(byte[] decapKey, byte[] encBuf, int encOff, byte[] secBuf, int secOff)
        {
            Debug.Assert(decapKey.Length == SecretKeyBytes);

            // TODO Input validation?
            byte[] buf = new byte[2 * SymBytes];
            m_indCpa.Decrypt(encBuf, encOff, decapKey, buf);
            Array.Copy(decapKey, SecretKeyBytes - 2 * SymBytes, buf, SymBytes, SymBytes);

            byte[] kr = new byte[2 * SymBytes];
            G(buf, kr);

            byte[] cmp = new byte[CipherTextBytes];
            m_indCpa.Encrypt(pk: decapKey, pkOff: IndCpaSecretKeyBytes, buf, 0, kr, SymBytes, cmp, 0);

            int fail = ~FixedTimeEquals(CipherTextBytes, cmp, 0, encBuf, encOff);

            // if ciphertexts do not match, “implicitly reject”
            {
                byte[] implicitRejection = new byte[SharedSecretBytes];

                // J(z||c)
                var xof = new ShakeDigest(256);
                xof.BlockUpdate(decapKey, SecretKeyBytes - SymBytes, SymBytes);
                xof.BlockUpdate(encBuf, encOff, CipherTextBytes);
                xof.OutputFinal(implicitRejection, 0, SharedSecretBytes);

                CMov(kr, implicitRejection, SharedSecretBytes, fail);
            }

            Array.Copy(kr, 0, secBuf, secOff, SharedSecretBytes);
        }

        internal void KemEncrypt(byte[] encapKey, byte[] randBytes, byte[] encBuf, int encOff, byte[] secBuf,
            int secOff)
        {
            Debug.Assert(encapKey.Length == PublicKeyBytes);
            Debug.Assert(randBytes.Length == SymBytes);

            byte[] buf = new byte[2 * SymBytes];
            byte[] kr = new byte[2 * SymBytes];

            Array.Copy(randBytes, 0, buf, 0, SymBytes);

            H(encapKey, 0, PublicKeyBytes, buf, SymBytes);

            G(buf, kr);

            m_indCpa.Encrypt(pk: encapKey, pkOff: 0, buf, 0, kr, SymBytes, encBuf, encOff);

            Array.Copy(kr, 0, secBuf, secOff, SharedSecretBytes);
        }

        [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
        private static void CMov(byte[] r, byte[] x, int xLen, int cond)
        {
            Debug.Assert(0 == cond || -1 == cond);

            for (int i = 0; i < xLen; ++i)
            {
                int r_i = r[i], diff = r_i ^ x[i];
                r_i ^= diff & cond;
                r[i] = (byte)r_i;
            }
        }

        [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
        public static int FixedTimeEquals(int len, byte[] a, int aOff, byte[] b, int bOff)
        {
            int d = 0;
            for (int i = 0; i < len; ++i)
            {
                d |= a[aOff + i] ^ b[bOff + i];
            }
            d |= d >> 16;
            d &= 0xFFFF;
            return (d - 1) >> 31;
        }
#endif
    }
}
