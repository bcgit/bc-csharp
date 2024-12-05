using System;
using System.Diagnostics;

using Org.BouncyCastle.Pqc.Crypto.SphincsPlus;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Kems.MLKem
{
    internal class MLKemEngine
    {
        private readonly IndCpa m_indCpa;
        private readonly SecureRandom m_random;

        // Constant Parameters
        internal const int N = 256;
        internal const int Q = 3329;
        internal const int QInv = 62209;

        internal const int SymBytes = 32;
        private const int SharedSecretBytes = 32;

        internal const int PolyBytes = 384;

        internal const int Eta2 = 2;

        internal int IndCpaMsgBytes = SymBytes;
        internal Symmetric Symmetric { get; private set; }


        // Parameters
        internal int K { get; private set; }
        internal int PolyVecBytes { get; private set; }
        internal int PolyCompressedBytes { get; private set; }
        internal int PolyVecCompressedBytes { get; private set; }
        internal int Eta1 { get; private set; }
        internal int IndCpaPublicKeyBytes { get; private set; }
        internal int IndCpaSecretKeyBytes { get; private set; }
        internal int IndCpaBytes { get; private set; }
        internal int PublicKeyBytes { get; private set; }
        internal int SecretKeyBytes { get; private set; }
        internal int CipherTextBytes { get; private set; }

        // Crypto
        internal int CryptoBytes { get; private set; }
        internal int CryptoSecretKeyBytes { get; private set; }
        internal int CryptoPublicKeyBytes { get; private set; }
        internal int CryptoCipherTextBytes { get; private set; }

        internal MLKemEngine(int k, SecureRandom random)
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
            }

            PolyVecBytes = k * PolyBytes;
            IndCpaPublicKeyBytes = PolyVecBytes + SymBytes;
            IndCpaSecretKeyBytes = PolyVecBytes;
            IndCpaBytes = PolyVecCompressedBytes + PolyCompressedBytes;
            PublicKeyBytes = IndCpaPublicKeyBytes;
            SecretKeyBytes = IndCpaSecretKeyBytes + IndCpaPublicKeyBytes + 2 * SymBytes;
            CipherTextBytes = IndCpaBytes;

            // Define Crypto Params
            CryptoBytes = SharedSecretBytes;
            CryptoSecretKeyBytes = SecretKeyBytes;
            CryptoPublicKeyBytes = PublicKeyBytes;
            CryptoCipherTextBytes = CipherTextBytes;
            Symmetric = new Symmetric.ShakeSymmetric();

            m_indCpa = new IndCpa(this);
            m_random = random;
        }

        internal void GenerateKemKeyPair(out byte[] t, out byte[] rho, out byte[] s, out byte[] hpk, out byte[] nonce,
            out byte[] seed)
        {
            byte[] d = new byte[SymBytes];
            byte[] z = new byte[SymBytes];
            m_random.NextBytes(d);
            m_random.NextBytes(z);

            GenerateKemKeyPairInternal(d, z, out t, out rho, out s, out hpk, out nonce, out seed);
        }

        internal void GenerateKemKeyPairInternal(byte[] d, byte[] z, out byte[] t, out byte[] rho, out byte[] s,
            out byte[] hpk, out byte[] nonce, out byte[] seed)
        {
            m_indCpa.GenerateKeyPair(d, out byte[] pk, out s);
            Debug.Assert(s.Length == IndCpaSecretKeyBytes);

            hpk = new byte[32];
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Symmetric.Hash_h(pk.AsSpan(), hpk.AsSpan());
#else
            Symmetric.Hash_h(pk, 0, pk.Length, hpk, 0);
#endif

            t = Arrays.CopyOfRange(pk, 0, IndCpaPublicKeyBytes - 32);
            rho = Arrays.CopyOfRange(pk, IndCpaPublicKeyBytes - 32, IndCpaPublicKeyBytes);
            nonce = z;
            seed = Arrays.Concatenate(d, z);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        internal void KemDecrypt(Span<byte> secret, ReadOnlySpan<byte> encapsulation, byte[] secretKey)
        {
            // TODO do input validation
            Span<byte> kr = stackalloc byte[2 * SymBytes];
            Span<byte> buf = stackalloc byte[2 * SymBytes];
            Span<byte> cmp = stackalloc byte[CipherTextBytes];
            ReadOnlySpan<byte> pk = secretKey.AsSpan(IndCpaSecretKeyBytes);
            Span<byte> implicit_rejection = stackalloc byte[SymBytes + CipherTextBytes];

            m_indCpa.Decrypt(buf, encapsulation, secretKey);
            secretKey.AsSpan(SecretKeyBytes - 2 * SymBytes, SymBytes).CopyTo(buf[SymBytes..]);

            Symmetric.Hash_g(buf, kr);

            m_indCpa.Encrypt(cmp, buf[..SymBytes], pk, kr[SymBytes..]);

            bool fail = !Arrays.FixedTimeEquals(cmp, encapsulation);

            Symmetric.Hash_h(encapsulation, kr[SymBytes..]);
            secretKey.AsSpan(SecretKeyBytes - SymBytes, SymBytes).CopyTo(implicit_rejection);
            encapsulation.CopyTo(implicit_rejection[SymBytes..]);
            Symmetric.Kdf(implicit_rejection, implicit_rejection);

            CMov(kr, implicit_rejection, SymBytes, fail);

            kr[..SharedSecretBytes].CopyTo(secret);
        }

        internal void KemEncrypt(Span<byte> encapsulation, Span<byte> secret, ReadOnlySpan<byte> pk,
            ReadOnlySpan<byte> randBytes)
        {
            //TODO: do input validation elsewhere?
            // Input validation (6.2 ML-KEM Encaps)
            // Type Check
            if (pk.Length != IndCpaPublicKeyBytes)
                throw new ArgumentException("Input validation Error: Type check failed for ml-kem encapsulation");

            // Modulus Check
            PolyVec polyVec = new PolyVec(this);
            byte[] seed = m_indCpa.UnpackPublicKey(polyVec, pk);
            byte[] ek = m_indCpa.PackPublicKey(polyVec, seed);
            if (!pk.SequenceEqual(ek))
                throw new ArgumentException("Input validation: Modulus check failed for ml-kem encapsulation");

            KemEncryptInternal(encapsulation, secret, pk, randBytes);
        }

        internal void KemEncryptInternal(Span<byte> encapsulation, Span<byte> secret, ReadOnlySpan<byte> pk,
            ReadOnlySpan<byte> randBytes)
        {
            Span<byte> buf = stackalloc byte[2 * SymBytes];
            Span<byte> kr = stackalloc byte[2 * SymBytes];

            randBytes[..SymBytes].CopyTo(buf);

            Symmetric.Hash_h(pk, buf[SymBytes..]);

            Symmetric.Hash_g(buf, kr);

            m_indCpa.Encrypt(encapsulation, buf[..SymBytes], pk, kr[SymBytes..]);

            kr[..SharedSecretBytes].CopyTo(secret);
        }

        private static void CMov(Span<byte> r, ReadOnlySpan<byte> x, int len, bool b)
        {
            if (b)
            {
                x[..len].CopyTo(r);
            }
            else
            {
                r[..len].CopyTo(r);
            }
        }
#else
        internal void KemDecrypt(byte[] secBuf, int secOff, byte[] encBuf, int encOff, byte[] secretKey)
        {
            //TODO do input validation
            byte[] buf = new byte[2 * SymBytes], kr = new byte[2 * SymBytes], cmp = new byte[CipherTextBytes];
            byte[] pk = Arrays.CopyOfRange(secretKey, IndCpaSecretKeyBytes, secretKey.Length);
            byte[] implicit_rejection = new byte[SymBytes + CipherTextBytes];
            m_indCpa.Decrypt(buf, encBuf, encOff, secretKey);
            Array.Copy(secretKey, SecretKeyBytes - 2 * SymBytes, buf, SymBytes, SymBytes);

            Symmetric.Hash_g(buf, kr);

            m_indCpa.Encrypt(cmp, 0, Arrays.CopyOf(buf, SymBytes), pk, Arrays.CopyOfRange(kr, SymBytes, kr.Length));

            bool fail = !Arrays.FixedTimeEquals(cmp.Length, cmp, 0, encBuf, encOff);

            Symmetric.Hash_h(encBuf, encOff, CipherTextBytes, kr, SymBytes);
            Array.Copy(secretKey, SecretKeyBytes - SymBytes, implicit_rejection, 0, SymBytes);
            Array.Copy(encBuf, encOff, implicit_rejection, SymBytes, CipherTextBytes);
            Symmetric.Kdf(implicit_rejection, implicit_rejection);

            CMov(kr, implicit_rejection, SymBytes, fail);

            Array.Copy(kr, 0, secBuf, secOff, SharedSecretBytes);
        }

        internal void KemEncrypt(byte[] encBuf, int encOff, byte[] secBuf, int secOff, byte[] pk, byte[] randBytes)
        {
            //TODO: do input validation elsewhere?
            // Input validation (6.2 ML-KEM Encaps)
            // Type Check
            if (pk.Length != IndCpaPublicKeyBytes)
                throw new ArgumentException("Input validation Error: Type check failed for ml-kem encapsulation");

            // Modulus Check
            PolyVec polyVec = new PolyVec(this);
            byte[] seed = m_indCpa.UnpackPublicKey(polyVec, pk);
            byte[] ek = m_indCpa.PackPublicKey(polyVec, seed);
            if (!Arrays.AreEqual(ek, pk))
                throw new ArgumentException("Input validation: Modulus check failed for ml-kem encapsulation");

            KemEncryptInternal(encBuf, encOff, secBuf, secOff, pk, randBytes);
        }

        internal void KemEncryptInternal(byte[] encBuf, int encOff, byte[] secBuf, int secOff, byte[] pk, byte[] randBytes)
        {
            byte[] buf = new byte[2 * SymBytes];
            byte[] kr = new byte[2 * SymBytes];

            Array.Copy(randBytes, 0, buf, 0, SymBytes);

            Symmetric.Hash_h(pk, 0, pk.Length, buf, SymBytes);

            Symmetric.Hash_g(buf, kr);

            m_indCpa.Encrypt(encBuf, encOff, Arrays.CopyOfRange(buf, 0, SymBytes), pk,
                Arrays.CopyOfRange(kr, SymBytes, 2 * SymBytes));

            Array.Copy(kr, 0, secBuf, secOff, SharedSecretBytes);
        }

        private static void CMov(byte[] r, byte[] x, int len, bool b)
        {
            if (b)
            {
                Array.Copy(x, 0, r, 0, len);
            }
            else
            {
                Array.Copy(r, 0, r, 0, len);
            }
        }
#endif

        internal void RandomBytes(byte[] buf, int len)
        {
            m_random.NextBytes(buf, 0, len);
        }
    }
}
