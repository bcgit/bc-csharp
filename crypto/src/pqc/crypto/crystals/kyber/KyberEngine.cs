using System;

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
        public Symmetric Symmetric { get; private set; }


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

        public KyberEngine(int k, bool usingAes)
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

            if (usingAes)
            {
                Symmetric = new Symmetric.AesSymmetric();
            }
            else
            {
                Symmetric = new Symmetric.ShakeSymmetric();
            }

            m_indCpa = new KyberIndCpa(this);
        }

        internal void Init(SecureRandom random)
        {
            m_random = random;
        }

        internal void GenerateKemKeyPair(out byte[] t, out byte[] rho, out byte[] s, out byte[] hpk, out byte[] nonce)
        {
            byte[] pk, sk;
            m_indCpa.GenerateKeyPair(out pk, out sk);
            s = Arrays.CopyOfRange(sk, 0, IndCpaSecretKeyBytes);
            
            hpk = new byte[32];
            Symmetric.Hash_h(hpk, pk, 0);

            nonce = new byte[SymBytes];
            m_random.NextBytes(nonce);
            
            t = Arrays.CopyOfRange(pk, 0, IndCpaPublicKeyBytes - 32);
            rho = Arrays.CopyOfRange(pk, IndCpaPublicKeyBytes - 32, IndCpaPublicKeyBytes);

        }

        internal void KemEncrypt(byte[] cipherText, byte[] sharedSecret, byte[] pk)
        {
            byte[] randBytes = new byte[SymBytes];
            byte[] buf = new byte[2 * SymBytes];
            byte[] kr = new byte[2 * SymBytes];

            m_random.NextBytes(randBytes, 0, SymBytes);

            Array.Copy(randBytes, 0, buf, 0, SymBytes);

            Symmetric.Hash_h(buf, pk, SymBytes);

            Symmetric.Hash_g(kr, buf);
            
            m_indCpa.Encrypt(cipherText, Arrays.CopyOfRange(buf, 0, SymBytes), pk, Arrays.CopyOfRange(kr, SymBytes, 2 * SymBytes));

            Array.Copy(kr, 0, sharedSecret, 0, sharedSecret.Length);
        }

        internal void KemDecrypt(byte[] sharedSecret, byte[] cipherText, byte[] secretKey)
        {
            byte[] buf = new byte[2 * SymBytes], kr = new byte[2 * SymBytes], cmp = new byte[CipherTextBytes];
            byte[] pk = Arrays.CopyOfRange(secretKey, IndCpaSecretKeyBytes, secretKey.Length);
            m_indCpa.Decrypt(buf, cipherText, secretKey);
            Array.Copy(secretKey, SecretKeyBytes - 2 * SymBytes, buf, SymBytes, SymBytes);

            Symmetric.Hash_g(kr, buf);


            m_indCpa.Encrypt(cmp, Arrays.CopyOf(buf, SymBytes), pk, Arrays.CopyOfRange(kr, SymBytes, kr.Length));

            bool fail = !Arrays.FixedTimeEquals(cipherText, cmp);
            
            Symmetric.Hash_h(kr, cipherText, SymBytes);


            CMov(kr, Arrays.CopyOfRange(secretKey, SecretKeyBytes - SymBytes, SecretKeyBytes), SymBytes, fail);

            Array.Copy(kr, 0, sharedSecret, 0, sharedSecret.Length);
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
        
        internal void RandomBytes(byte[] buf, int len)
        {
            m_random.NextBytes(buf,0,len);
        }
    }
}


