using System;

using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.MLKem
{
    internal class MLKemEngine
    {
        private SecureRandom m_random;
        private readonly MLKemIndCpa m_indCpa;
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

            m_indCpa = new MLKemIndCpa(this);
        }

        internal void Init(SecureRandom random)
        {
            m_random = random;
        }

        internal void GenerateKemKeyPair(out byte[] t, out byte[] rho, out byte[] s, out byte[] hpk, out byte[] nonce)
        {
            m_indCpa.GenerateKeyPair(out byte[] pk, out byte[] sk);
            s = Arrays.CopyOfRange(sk, 0, IndCpaSecretKeyBytes);

            hpk = new byte[32];
            Symmetric.Hash_h(hpk, pk, 0);

            nonce = new byte[SymBytes];
            m_random.NextBytes(nonce);

            t = Arrays.CopyOfRange(pk, 0, IndCpaPublicKeyBytes - 32);
            rho = Arrays.CopyOfRange(pk, IndCpaPublicKeyBytes - 32, IndCpaPublicKeyBytes);
        }

        internal byte[][] GenerateKemKeyPairInternal(byte[] d, byte[] z)
        {
            m_indCpa.GenerateKeyPair(d, out byte[] pk, out byte[] sk);

            byte[] s = new byte[IndCpaSecretKeyBytes];
            Array.Copy(sk, 0, s, 0, IndCpaSecretKeyBytes);


            byte[] hashedPublicKey = new byte[32];
            Symmetric.Hash_h(hashedPublicKey, pk, 0);

            byte[] outputPublicKey = new byte[IndCpaPublicKeyBytes];

            Array.Copy(pk, 0, outputPublicKey, 0, IndCpaPublicKeyBytes);
            return new byte[][] { Arrays.CopyOfRange(outputPublicKey, 0, outputPublicKey.Length - 32), Arrays.CopyOfRange(outputPublicKey, outputPublicKey.Length - 32, outputPublicKey.Length), s, hashedPublicKey, z };
        }

        internal void KemEncrypt(byte[] cipherText, byte[] sharedSecret, byte[] pk, byte[] randBytes)
        {
            //TODO: do input validation elsewhere?
            // Input validation (6.2 ML-KEM Encaps)
            // Type Check
            if (pk.Length != IndCpaPublicKeyBytes)
            {
                throw new ArgumentException("Input validation Error: Type check failed for ml-kem encapsulation");
            }
            // Modulus Check
            PolyVec polyVec = new PolyVec(this);
            byte[] seed = m_indCpa.UnpackPublicKey(polyVec, pk);
            byte[] ek = m_indCpa.PackPublicKey(polyVec, seed);
            if (!Arrays.AreEqual(ek, pk))
            {
                throw new ArgumentException("Input validation: Modulus check failed for ml-kem encapsulation");
            }
            KemEncryptInternal(cipherText, sharedSecret, pk, randBytes);
        }

        internal void KemEncryptInternal(byte[] cipherText, byte[] sharedSecret, byte[] pk, byte[] randBytes)
        {
            byte[] buf = new byte[2 * SymBytes];
            byte[] kr = new byte[2 * SymBytes];

            Array.Copy(randBytes, 0, buf, 0, SymBytes);

            Symmetric.Hash_h(buf, pk, SymBytes);

            Symmetric.Hash_g(kr, buf);

            m_indCpa.Encrypt(cipherText, Arrays.CopyOfRange(buf, 0, SymBytes), pk, Arrays.CopyOfRange(kr, SymBytes, 2 * SymBytes));

            Array.Copy(kr, 0, sharedSecret, 0, sharedSecret.Length);
        }

        internal void KemDecrypt(byte[] sharedSecret, byte[] cipherText, byte[] secretKey)
        {
            //TODO do input validation
            byte[] buf = new byte[2 * SymBytes], kr = new byte[2 * SymBytes], cmp = new byte[CipherTextBytes];
            byte[] pk = Arrays.CopyOfRange(secretKey, IndCpaSecretKeyBytes, secretKey.Length);
            byte[] implicit_rejction = new byte[SymBytes + CipherTextBytes];
            m_indCpa.Decrypt(buf, cipherText, secretKey);
            Array.Copy(secretKey, SecretKeyBytes - 2 * SymBytes, buf, SymBytes, SymBytes);

            Symmetric.Hash_g(kr, buf);


            m_indCpa.Encrypt(cmp, Arrays.CopyOf(buf, SymBytes), pk, Arrays.CopyOfRange(kr, SymBytes, kr.Length));

            bool fail = !Arrays.FixedTimeEquals(cipherText, cmp);

            Symmetric.Hash_h(kr, cipherText, SymBytes);
            Array.Copy(secretKey, SecretKeyBytes - SymBytes, implicit_rejction, 0, SymBytes);
            Array.Copy(cipherText, 0, implicit_rejction, SymBytes, CipherTextBytes);
            Symmetric.Kdf(implicit_rejction, implicit_rejction);

            CMov(kr, implicit_rejction, SymBytes, fail);

            Array.Copy(kr, 0, sharedSecret, 0, sharedSecret.Length);
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

        internal void RandomBytes(byte[] buf, int len)
        {
            m_random.NextBytes(buf, 0, len);
        }
    }
}
