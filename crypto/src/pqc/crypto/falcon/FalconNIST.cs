using System;

using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.Falcon
{
    internal sealed class FalconNist
    {
        private readonly SecureRandom m_random;
        private readonly int m_logN;
        private readonly int m_nonceLength;
        private readonly int CRYPTO_BYTES;
        private readonly int CRYPTO_PUBLICKEYBYTES;
        private readonly int CRYPTO_SECRETKEYBYTES;

        internal int NonceLength => m_nonceLength;
        internal int LogN => m_logN;
        internal int CryptoBytes => this.CRYPTO_BYTES;

        internal FalconNist(SecureRandom random, int logN, int nonceLength)
        {
            m_logN = logN;
            m_random = random;
            m_nonceLength = nonceLength;
            int n = 1 << logN;
            this.CRYPTO_PUBLICKEYBYTES = 1 + (14 * n / 8);
            if (logN == 10)
            {
                this.CRYPTO_SECRETKEYBYTES = 2305;
                this.CRYPTO_BYTES = 1330;
            }
            else if (logN == 9 || logN == 8)
            {
                this.CRYPTO_SECRETKEYBYTES = 1 + (6 * n * 2 / 8) + n;
                this.CRYPTO_BYTES = 690; // TODO find what the byte length is here when not at degree 9 or 10
            }
            else if (logN == 7 || logN == 6)
            {
                this.CRYPTO_SECRETKEYBYTES = 1 + (7 * n * 2 / 8) + n;
                this.CRYPTO_BYTES = 690;
            }
            else
            {
                this.CRYPTO_SECRETKEYBYTES = 1 + (n * 2) + n;
                this.CRYPTO_BYTES = 690;
            }
        }

        internal int crypto_sign_keypair(out byte[] pk, out byte[] fEnc, out byte[] gEnc, out byte[] FEnc)
        {
            byte[] sk = new byte[CRYPTO_SECRETKEYBYTES];
            pk = new byte[CRYPTO_PUBLICKEYBYTES];
            int n = 1 << m_logN;
            sbyte[] f = new sbyte[n], g = new sbyte[n], F = new sbyte[n];
            ushort[] h = new ushort[n];

            /*
            * Generate key pair.
            */
            {
                byte[] seed = new byte[48];
                m_random.NextBytes(seed);

                SHAKE256 rng = new SHAKE256();
                rng.i_shake256_init();
                rng.i_shake256_inject(seed, 0, seed.Length);
                rng.i_shake256_flip();

                FalconKeyGen.KeyGen(rng, f, 0, g, 0, F, 0, null, 0, h, 0, m_logN);
            }

            // TODO check which exception types to use here

            /*
            * Encode private key.
            */
            sk[0] = (byte)(0x50 + m_logN);
            int u = 1;
            int v = FalconCodec.trim_i8_encode(sk, u, CRYPTO_SECRETKEYBYTES - u,
                f, 0, m_logN, FalconCodec.max_fg_bits[m_logN]);
            if (v == 0)
                throw new InvalidOperationException("f encode failed");

            fEnc = Arrays.CopyOfRange(sk, u, u + v);
            u += v;
            v = FalconCodec.trim_i8_encode(sk, u, CRYPTO_SECRETKEYBYTES - u,
                g, 0, m_logN, FalconCodec.max_fg_bits[m_logN]);
            if (v == 0)
                throw new InvalidOperationException("g encode failed");

            gEnc = Arrays.CopyOfRange(sk, u, u + v);
            u += v;
            v = FalconCodec.trim_i8_encode(sk,  u, CRYPTO_SECRETKEYBYTES - u,
                F, 0, m_logN, FalconCodec.max_FG_bits[m_logN]);
            if (v == 0)
                throw new InvalidOperationException("F encode failed");

            FEnc = Arrays.CopyOfRange(sk, u, u + v);
            u += v;
            if (u != CRYPTO_SECRETKEYBYTES)
                 throw new InvalidOperationException("secret key encoding failed");

            /*
            * Encode public key.
            */
            pk[0] = (byte)(0x00 + m_logN);
            v = FalconCodec.modq_encode(pk, 1, CRYPTO_PUBLICKEYBYTES - 1, h, 0, m_logN);
            if (v != CRYPTO_PUBLICKEYBYTES - 1)
                 throw new InvalidOperationException("public key encoding failed");

            pk = Arrays.CopyOfRange(pk, 1, pk.Length);

            return 0;
        }

        internal byte[] crypto_sign(bool attached, byte[] sm, byte[] m, int mOff, int mLen, byte[] sk, int skOff)
        {
            // TEMPALLOC union {
            //     uint8_t b[72 * 1024];
            //     uint64_t dummy_u64;
            //     fpr dummy_fpr;
            // } tmp;

            int n = 1 << m_logN;
            sbyte[] f = new sbyte[n],
                    g = new sbyte[n],
                    F = new sbyte[n],
                    G = new sbyte[n];
            
            short[] sig = new short[n];
            ushort[] hm = new ushort[n];
            
            byte[] seed = new byte[48],
                   nonce = new byte[m_nonceLength];

            byte[] esig = new byte[this.CRYPTO_BYTES - 2 - m_nonceLength];
            SHAKE256 sc = new SHAKE256();

            // /*
            // * Decode the private key.
            // */
            // if (sksrc[sk+0] != 0x50 + this.logn) {
            //     throw new ArgumentException("private key header incorrect");
            // }
            int u = 0;
            int v = FalconCodec.trim_i8_decode(f, 0, m_logN, FalconCodec.max_fg_bits[m_logN], sk, skOff + u,
                CRYPTO_SECRETKEYBYTES - u);
            if (v == 0)
                throw new InvalidOperationException("f decode failed");

            u += v;
            v = FalconCodec.trim_i8_decode(g, 0, m_logN, FalconCodec.max_fg_bits[m_logN], sk, skOff + u,
                CRYPTO_SECRETKEYBYTES - u);
            if (v == 0)
                throw new InvalidOperationException("g decode failed");

            u += v;
            v = FalconCodec.trim_i8_decode(F, 0, m_logN, FalconCodec.max_FG_bits[m_logN], sk, skOff + u,
                CRYPTO_SECRETKEYBYTES - u);
            if (v == 0) 
                throw new InvalidOperationException("F decode failed");

            u += v;
            if (u != CRYPTO_SECRETKEYBYTES - 1) 
                throw new InvalidOperationException("full Key not used");

            if (FalconVrfy.complete_private(G, 0, f, 0, g, 0, F, 0, m_logN, new ushort[2 * n], 0) == 0)
                throw new InvalidOperationException("complete private failed");

            /*
            * Create a random nonce (40 bytes).
            */
            m_random.NextBytes(nonce);

            /*
            * Hash message nonce + message into a vector.
            */
            sc.i_shake256_init();
            sc.i_shake256_inject(nonce,0,nonce.Length);
            sc.i_shake256_inject(m, mOff, mLen);
            sc.i_shake256_flip();
            FalconCommon.hash_to_point_vartime(sc, hm, 0, m_logN);

            /*
            * Initialize a RNG.
            */
            m_random.NextBytes(seed);
            sc.i_shake256_init();
            sc.i_shake256_inject(seed, 0, seed.Length);
            sc.i_shake256_flip();

            /*
            * Compute the signature.
            */
            FalconSign.sign_dyn(sig, 0, sc, f, 0, g, 0, F, 0, G, 0, hm, 0, m_logN, new FalconFPR[10 * n], 0);

            int sig_len;
            if (attached)
            {
                /*
                 * Encode the signature. Format is:
                 *   signature header     1 bytes
                 *   nonce                40 bytes
                 *   signature            slen bytes
                 */
                esig[0] = (byte)(0x20 + m_logN);
                sig_len = FalconCodec.comp_encode(esig, 1, esig.Length - 1, sig, 0, m_logN);
                if (sig_len == 0)
                    throw new InvalidOperationException("signature failed to generate");

                sig_len++;
            }
            else
            {
                sig_len = FalconCodec.comp_encode(esig, 0, esig.Length, sig, 0, m_logN);
                if (sig_len == 0)
                    throw new InvalidOperationException("signature failed to generate");
            }

            // header
            sm[0] = (byte)(0x30 + m_logN);
            // nonce
            Array.Copy(nonce, 0, sm, 1, m_nonceLength);

            // signature
            Array.Copy(esig, 0, sm, 1 + m_nonceLength, sig_len);

            return Arrays.CopyOfRange(sm, 0, 1 + m_nonceLength + sig_len);
        }

        internal int crypto_sign_open(bool attached, byte[] sig_encoded, byte[] nonce, byte[] m, byte[] pksrc, int pk)
        {
            int sig_len, msg_len;
            int n = 1 << m_logN;
            ushort[] h = new ushort[n],
                     hm = new ushort[n];
            short[] sig = new short[n];
            SHAKE256 sc = new SHAKE256();

            /*
            * Decode public key.
            */
            // if (pksrc[pk+0] != 0x00 + this.logn) {
            //     return -1;
            // }
            if (FalconCodec.modq_decode(h, 0, m_logN, pksrc, pk, CRYPTO_PUBLICKEYBYTES - 1)
                != CRYPTO_PUBLICKEYBYTES - 1)
            {
                return -1;
            }
            FalconVrfy.to_ntt_monty(h, 0, m_logN);

            /*
            * Find nonce, signature, message length.
            */
            // if (smlen < 2 + this.noncelen) {
            //     return -1;
            // }
            // sig_len = ((int)sm[0] << 8) | (int)sm[1];
            sig_len = sig_encoded.Length;
            // if (sig_len > (smlen - 2 - this.noncelen)) {
            //     return -1;
            // }
            // msg_len = smlen - 2 - this.noncelen - sig_len;
            msg_len = m.Length;

            /*
            * Decode signature.
            */
            // esig = sm + 2 + this.noncelen + msg_len;
            if (attached)
            {
                if (sig_len < 1 || sig_encoded[0] != (byte)(0x20 + m_logN))
                    return -1;

                if (FalconCodec.comp_decode(sig, 0, m_logN, sig_encoded, 1, sig_len - 1) != sig_len - 1)
                    return -1;
            }
            else
            {
                if (sig_len < 1 || FalconCodec.comp_decode(sig, 0, m_logN, sig_encoded, 0, sig_len) != sig_len)
                    return -1;
            }

            /*
            * Hash nonce + message into a vector.
            */
            sc.i_shake256_init();
            // sc.i_shake256_inject(sm + 2, this.noncelen + msg_len);
            sc.i_shake256_inject(nonce, 0, m_nonceLength);
            sc.i_shake256_inject(m, 0, m.Length);
            sc.i_shake256_flip();
            FalconCommon.hash_to_point_vartime(sc, hm, 0, m_logN);

            /*
            * Verify signature.
            */
            if (!FalconVrfy.verify_raw(hm, 0, sig, 0, h, 0, m_logN, new ushort[n], 0))
                return -1;

            /*
            * Return plaintext. - not in use
            */
            // Array.Copy(sm + 2 + this.noncelen, m, msg_len);
            // *mlen = msg_len;
            return 0;
        }
    }
}
