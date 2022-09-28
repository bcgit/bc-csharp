using System;

using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber
{
    internal class KyberEngine
    {
        private SecureRandom m_random;
        private KyberIndCpa m_indCpa;

        // Constant Parameters
        public const int N = 256;
        public const int Q = 3329;
        public const int QInv = 62209;

        public static int SymBytes = 32;
        private const int SharedSecretBytes = 32;

        public static int PolyBytes = 384;

        public const int Eta2 = 2;

        public int IndCpaMsgBytes = SymBytes;


        // Parameters
        public int K { get; private set; }
        public int PolyVecBytes { get; private set; }
        public int PolyCompressedBytes { get; private set; }
        public int PolyVecCompressedBytes { get; private set; }
        public int Eta1 { get; private set; }
        public int IndCpaPublicKeyBytes { get; private set; }
        public int IndCpaSecretKeyBytes { get; private set; }
        public int IndCpaBytes { get; private set; }
        public int PublicKeyBytes { get; private set; }
        public int SecretKeyBytes { get; private set; }
        public int CipherTextBytes { get; private set; }

        // Crypto
        public int CryptoBytes { get; private set; }
        public int CryptoSecretKeyBytes { get; private set; }
        public int CryptoPublicKeyBytes { get; private set; }
        public int CryptoCipherTextBytes { get; private set; }

        internal KyberEngine(int k)
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

            m_indCpa = new KyberIndCpa(this);
        }

        internal void Init(SecureRandom random)
        {
            m_random = random;
        }

        internal void UpdateSeed(byte[] seed)
        {
            m_random.SetSeed(seed);
        }

        internal void GenerateKemKeyPair(byte[] pk, byte[] sk)
        {
            Sha3Digest Sha3Digest256 = new Sha3Digest(256);
            m_indCpa.GenerateKeyPair(pk, sk);
            Array.Copy(pk, 0, sk, IndCpaSecretKeyBytes, IndCpaPublicKeyBytes);
            Sha3Digest256.BlockUpdate(pk, 0, PublicKeyBytes);
            Sha3Digest256.DoFinal(sk, SecretKeyBytes - 2 * SymBytes);
            m_random.NextBytes(sk, SecretKeyBytes - SymBytes, SymBytes);            
        }

        internal void KemEncrypt(byte[] cipherText, byte[] sharedSecret, byte[] pk)
        {
            byte[] buf = new byte[2 * SymBytes];
            byte[] kr = new byte[2 * SymBytes];

            Sha3Digest Sha3Digest256 = new Sha3Digest(256);

            m_random.NextBytes(buf, 0, SymBytes);

            Sha3Digest256.BlockUpdate(buf, 0, SymBytes);
            Sha3Digest256.DoFinal(buf, 0);

            Sha3Digest256.BlockUpdate(pk, 0, PublicKeyBytes);
            Sha3Digest256.DoFinal(buf, SymBytes);

            Sha3Digest Sha3Digest512 = new Sha3Digest(512);
            Sha3Digest512.BlockUpdate(buf, 0, 2 * SymBytes);
            Sha3Digest512.DoFinal(kr, 0);

            m_indCpa.Encrypt(cipherText, Arrays.CopyOfRange(buf, 0, SymBytes), pk, Arrays.CopyOfRange(kr, SymBytes, 2 * SymBytes));
            Sha3Digest256.BlockUpdate(cipherText, 0, CipherTextBytes);
            Sha3Digest256.DoFinal(kr, SymBytes);

            ShakeDigest ShakeDigest128 = new ShakeDigest(256);
            
            ShakeDigest128.BlockUpdate(kr, 0, 2 * SymBytes);
            ShakeDigest128.DoFinal(sharedSecret, 0, SymBytes);
        }

        internal void KemDecrypt(byte[] sharedSecret, byte[] cipherText, byte[] secretKey)
        {
            byte[] buf = new byte[2 * SymBytes], kr = new byte[2 * SymBytes], cmp = new byte[CipherTextBytes];
            byte[] pk = Arrays.CopyOfRange(secretKey, IndCpaSecretKeyBytes, secretKey.Length);
            m_indCpa.Decrypt(buf, cipherText, secretKey);
            Array.Copy(secretKey, SecretKeyBytes - 2 * SymBytes, buf, SymBytes, SymBytes);

            Sha3Digest Sha3Digest512 = new Sha3Digest(512);
            Sha3Digest512.BlockUpdate(buf, 0, 2 * SymBytes);
            Sha3Digest512.DoFinal(kr, 0);

            m_indCpa.Encrypt(cmp, Arrays.CopyOf(buf, SymBytes), pk, Arrays.CopyOfRange(kr, SymBytes, kr.Length));

            bool fail = !Arrays.ConstantTimeAreEqual(cipherText, cmp);

            Sha3Digest Sha3Digest256 = new Sha3Digest(256);
            Sha3Digest256.BlockUpdate(cipherText, 0, CipherTextBytes);
            Sha3Digest256.DoFinal(kr, SymBytes);

            CMov(kr, Arrays.CopyOfRange(secretKey, SecretKeyBytes - SymBytes, SecretKeyBytes), SymBytes, fail);

            ShakeDigest ShakeDigest256 = new ShakeDigest(256);
            ShakeDigest256.BlockUpdate(kr, 0, 2 * SymBytes);
            ShakeDigest256.DoFinal(sharedSecret, 0, SymBytes);
        }

        internal void RandomBytes(byte[] buf, int len)
        {
            m_random.NextBytes(buf, 0, len);
        }

        private void CMov(byte[] r, byte[] x, int len, bool b)
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
    }
}


