using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;

using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
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

        internal const int IndCpaMsgBytes = SymBytes;
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

        internal bool CheckModulus(byte[] t) => PolyVec.CheckModulus(this, t) < 0;

        internal void GenerateKemKeyPair(SecureRandom random, out byte[] t, out byte[] rho, out byte[] s,
            out byte[] hpk, out byte[] nonce, out byte[] seed)
        {
            byte[] d = new byte[SymBytes];
            byte[] z = new byte[SymBytes];
            random.NextBytes(d);
            random.NextBytes(z);

            GenerateKemKeyPairInternal(d, z, out t, out rho, out s, out hpk, out nonce, out seed);
        }

        internal void GenerateKemKeyPairInternal(byte[] d, byte[] z, out byte[] t, out byte[] rho, out byte[] s,
            out byte[] hpk, out byte[] nonce, out byte[] seed)
        {
            m_indCpa.GenerateKeyPair(d, out byte[] pk, out s);
            Debug.Assert(s.Length == IndCpaSecretKeyBytes);

            hpk = new byte[32];
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            H(pk.AsSpan(), hpk.AsSpan());
#else
            H(pk, 0, pk.Length, hpk, 0);
#endif

            t = Arrays.CopyOfRange(pk, 0, IndCpaPublicKeyBytes - 32);
            rho = Arrays.CopyOfRange(pk, IndCpaPublicKeyBytes - 32, IndCpaPublicKeyBytes);
            nonce = z;
            seed = Arrays.Concatenate(d, z);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        internal static void G(ReadOnlySpan<byte> input, Span<byte> output) =>
            ImplDigest(new Sha3Digest(512), input, output);

        private static void H(ReadOnlySpan<byte> input, Span<byte> output) =>
            ImplDigest(new Sha3Digest(256), input, output);

        private static void ImplDigest(IDigest digest, ReadOnlySpan<byte> input, Span<byte> output)
        {
            digest.BlockUpdate(input);
            digest.DoFinal(output);
        }

        internal void KemDecrypt(Span<byte> secret, ReadOnlySpan<byte> encapsulation,
            MLKemPrivateKeyParameters privateKey)
        {
            byte[] decapKey = privateKey.GetEncoded();

            // TODO Input validation?
            Span<byte> kr = stackalloc byte[2 * SymBytes];
            Span<byte> buf = stackalloc byte[2 * SymBytes];
            Span<byte> cmp = stackalloc byte[CipherTextBytes];
            ReadOnlySpan<byte> pk = decapKey.AsSpan(IndCpaSecretKeyBytes);

            m_indCpa.Decrypt(buf, encapsulation, decapKey);
            decapKey.AsSpan(SecretKeyBytes - 2 * SymBytes, SymBytes).CopyTo(buf[SymBytes..]);

            G(buf, kr);

            m_indCpa.Encrypt(cmp, buf[..SymBytes], pk, kr[SymBytes..]);

            int fail = ~FixedTimeEquals(cmp, encapsulation);

            // if ciphertexts do not match, “implicitly reject”
            {
                Span<byte> implicitRejection = stackalloc byte[SharedSecretBytes];

                // J(z||c)
                var xof = new ShakeDigest(256);
                xof.BlockUpdate(decapKey.AsSpan(SecretKeyBytes - SymBytes, SymBytes));
                xof.BlockUpdate(encapsulation);
                xof.OutputFinal(implicitRejection);

                CMov(kr, implicitRejection, SharedSecretBytes, fail);
            }

            kr[..SharedSecretBytes].CopyTo(secret);
        }

        internal void KemEncrypt(Span<byte> encapsulation, Span<byte> secret, MLKemPublicKeyParameters publicKey,
            ReadOnlySpan<byte> randBytes)
        {
            ReadOnlySpan<byte> pk = publicKey.GetEncoded();

            Span<byte> buf = stackalloc byte[2 * SymBytes];
            Span<byte> kr = stackalloc byte[2 * SymBytes];

            randBytes[..SymBytes].CopyTo(buf);

            H(pk, buf[SymBytes..]);

            G(buf, kr);

            m_indCpa.Encrypt(encapsulation, buf[..SymBytes], pk, kr[SymBytes..]);

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

        private static void ImplDigest(IDigest digest, byte[] inBuf, int inOff, int inLen, byte[] outBuf, int outOff)
        {
            digest.BlockUpdate(inBuf, inOff, inLen);
            digest.DoFinal(outBuf, outOff);
        }

        internal void KemDecrypt(byte[] secBuf, int secOff, byte[] encBuf, int encOff,
            MLKemPrivateKeyParameters privateKey)
        {
            byte[] decapKey = privateKey.GetEncoded();

            // TODO Input validation?
            byte[] buf = new byte[2 * SymBytes], kr = new byte[2 * SymBytes], cmp = new byte[CipherTextBytes];
            byte[] pk = Arrays.CopyOfRange(decapKey, IndCpaSecretKeyBytes, decapKey.Length);
            m_indCpa.Decrypt(buf, encBuf, encOff, decapKey);
            Array.Copy(decapKey, SecretKeyBytes - 2 * SymBytes, buf, SymBytes, SymBytes);

            G(buf, kr);

            m_indCpa.Encrypt(cmp, 0, Arrays.CopyOf(buf, SymBytes), pk, Arrays.CopyOfRange(kr, SymBytes, kr.Length));

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

        internal void KemEncrypt(byte[] encBuf, int encOff, byte[] secBuf, int secOff,
            MLKemPublicKeyParameters publicKey, byte[] randBytes)
        {
            byte[] pk = publicKey.GetEncoded();

            byte[] buf = new byte[2 * SymBytes];
            byte[] kr = new byte[2 * SymBytes];

            Array.Copy(randBytes, 0, buf, 0, SymBytes);

            H(pk, 0, pk.Length, buf, SymBytes);

            G(buf, kr);

            m_indCpa.Encrypt(encBuf, encOff, Arrays.CopyOfRange(buf, 0, SymBytes), pk,
                Arrays.CopyOfRange(kr, SymBytes, 2 * SymBytes));

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
