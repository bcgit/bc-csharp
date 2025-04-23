using System;

using Org.BouncyCastle.Pqc.Crypto.Ntru.ParameterSets;
using Org.BouncyCastle.Pqc.Crypto.Ntru.Polynomials;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.Ntru.Owcpa
{
    /// <summary>
    /// An OW-CPA secure deterministic public key encryption scheme (DPKE).
    /// </summary>
    internal class NtruOwcpa
    {
        private readonly NtruParameterSet _parameterSet;
        private readonly NtruSampling _sampling;

        internal NtruOwcpa(NtruParameterSet parameterSet)
        {
            _parameterSet = parameterSet;
            _sampling = new NtruSampling(parameterSet);
        }

        /// <summary>
        /// Generate a DPKE key pair.
        /// </summary>
        /// <param name="seed">a random byte array</param>
        /// <returns>DPKE key pair</returns>
        internal OwcpaKeyPair KeyPair(byte[] seed)
        {
            byte[] publicKey;
            var privateKey = new byte[_parameterSet.OwcpaSecretKeyBytes()];
            var n = _parameterSet.N;

            int i;
            Polynomial x3 = _parameterSet.CreatePolynomial();
            Polynomial x4 = _parameterSet.CreatePolynomial();
            Polynomial x5 = _parameterSet.CreatePolynomial();

            PolynomialPair pair = _sampling.SampleFg(seed);
            Polynomial f = pair.F();
            Polynomial g = pair.G();

            x3.S3Inv(f);
            f.S3ToBytes(privateKey, 0);
            x3.S3ToBytes(privateKey, _parameterSet.PackTrinaryBytes());


            f.Z3ToZq();
            g.Z3ToZq();

            if (_parameterSet is NtruHrssParameterSet)
            {
                /* g = 3*(x-1)*g */
                for (i = n - 1; i > 0; i--)
                {
                    g.coeffs[i] = (ushort)(3 * (g.coeffs[i - 1] - g.coeffs[i]));
                }

                g.coeffs[0] = (ushort)-(3 * g.coeffs[0]);
            }
            else
            {
                for (i = 0; i < n; i++)
                {
                    g.coeffs[i] = (ushort)(3 * g.coeffs[i]);
                }
            }

            x3.RqMul(g, f);
            x4.RqInv(x3);

            x5.RqMul(x4, f);
            x3.SqMul(x5, f);
            var sqRes = x3.SqToBytes(privateKey.Length - 2 * _parameterSet.PackTrinaryBytes());
            Array.Copy(sqRes, 0, privateKey, 2 * _parameterSet.PackTrinaryBytes(), sqRes.Length);

            x5.RqMul(x4, g);
            x3.RqMul(x5, g);
            publicKey = x3.RqSumZeroToBytes(_parameterSet.OwcpaPublicKeyBytes());

            return new OwcpaKeyPair(publicKey, privateKey);
        }

        /// <summary>
        /// DPKE encryption.
        /// </summary>
        /// <param name="r"></param>
        /// <param name="m"></param>
        /// <param name="publicKey"></param>
        /// <returns>DPKE ciphertext</returns>
        internal byte[] Encrypt(Polynomial r, Polynomial m, byte[] publicKey)
        {
            int i;
            Polynomial x1 = _parameterSet.CreatePolynomial(); // h, liftm
            Polynomial x2 = _parameterSet.CreatePolynomial(); // ct

            x1.RqSumZeroFromBytes(publicKey);

            x2.RqMul(r, x1);

            x1.Lift(m);

            for (i = 0; i < _parameterSet.N; i++)
            {
                x2.coeffs[i] += x1.coeffs[i];
            }

            return x2.RqSumZeroToBytes(_parameterSet.NtruCiphertextBytes());
        }

        /// <summary>
        /// DPKE decryption.
        /// </summary>
        /// <param name="ciphertext"></param>
        /// <param name="privateKey"></param>
        /// <returns>an instance of <see cref="OwcpaDecryptResult"/> containing <c>packed_rm</c> an  fail flag</returns>
        internal OwcpaDecryptResult Decrypt(byte[] ciphertext, byte[] privateKey)
        {
            byte[] rm = new byte[_parameterSet.OwcpaMsgBytes()];
            int i, fail;
            Polynomial x1 = _parameterSet.CreatePolynomial(); // c, b
            Polynomial x2 = _parameterSet.CreatePolynomial(); // f, mf, liftm
            Polynomial x3 = _parameterSet.CreatePolynomial(); // cf, finv3, invh
            Polynomial x4 = _parameterSet.CreatePolynomial(); // m, r

            x1.RqSumZeroFromBytes(ciphertext);
            x2.S3FromBytes(privateKey);

            x2.Z3ToZq();

            x3.RqMul(x1, x2);

            x2.RqToS3(x3);

            x3.S3FromBytes(Arrays.CopyOfRange(privateKey, _parameterSet.PackTrinaryBytes(), privateKey.Length));

            x4.S3Mul(x2, x3);

            //m.S3ToBytes(rm, 0);
            x4.S3ToBytes(rm, _parameterSet.PackTrinaryBytes());

            fail = 0;

            /* Check that the unused bits of the last byte of the ciphertext are zero */
            fail |= CheckCiphertext(ciphertext);

            /* For the IND-CCA2 KEM we must ensure that c = Enc(h, (r,m)).             */
            /* We can avoid re-computing r*h + Lift(m) as long as we check that        */
            /* r (defined as b/h mod (q, Phi_n)) and m are in the message space.       */
            /* (m can take any value in S3 in NTRU_HRSS) */


            if (_parameterSet is NtruHpsParameterSet)
            {
                fail |= CheckM((HpsPolynomial)x4);
            }

            /* b = c - Lift(m) mod (q, x^n - 1) */
            x2.Lift(x4);

            for (i = 0; i < _parameterSet.N; i++)
            {
                x1.coeffs[i] = (ushort)(x1.coeffs[i] - x2.coeffs[i]);
            }

            /* r = b / h mod (q, Phi_n) */
            x3.SqFromBytes(Arrays.CopyOfRange(privateKey, 2 * _parameterSet.PackTrinaryBytes(), privateKey.Length));
            x4.SqMul(x1, x3);

            fail |= CheckR(x4);

            x4.TrinaryZqToZ3();
            x4.S3ToBytes(rm, 0);

            return new OwcpaDecryptResult(rm, fail);
        }

        private int CheckCiphertext(byte[] ciphertext)
        {
            ushort t;
            t = ciphertext[_parameterSet.NtruCiphertextBytes() - 1];
            t &= (ushort)(0xff << (8 - (7 & (_parameterSet.LogQ * _parameterSet.PackDegree()))));

            /* We have 0 <= t < 256 */
            /* Return 0 on success (t=0), 1 on failure */
            return 1 & ((~t + 1) >> 15);
        }

        private int CheckR(Polynomial r)
        {
            /* A valid r has coefficients in {0,1,q-1} and has r[N-1] = 0 */
            /* Note: We may assume that 0 <= r[i] <= q-1 for all i        */
            int i;
            int t = 0; // unsigned
            ushort c; // unsigned
            for (i = 0; i < _parameterSet.N - 1; i++)
            {
                c = r.coeffs[i];
                t |= (c + 1) & (_parameterSet.Q() - 4); /* 0 iff c is in {-1,0,1,2} */
                t |= (c + 2) & 4; /* 1 if c = 2, 0 if c is in {-1,0,1} */
            }

            t |= r.coeffs[_parameterSet.N - 1]; /* Coefficient n-1 must be zero */

            /* We have 0 <= t < 2^16. */
            /* Return 0 on success (t=0), 1 on failure */
            return (1 & ((~t + 1) >> 31));
        }

        private int CheckM(HpsPolynomial m)
        {
            int i;
            int t = 0; // unsigned
            ushort ps = 0; // unsigned
            ushort ms = 0; // unsigned
            for (i = 0; i < _parameterSet.N - 1; i++)
            {
                ps += (ushort)(m.coeffs[i] & 1);
                ms += (ushort)(m.coeffs[i] & 2);
            }

            t |= ps ^ (ms >> 1);
            t |= ms ^ ((NtruHpsParameterSet)_parameterSet).Weight();

            /* We have 0 <= t < 2^16. */
            /* Return 0 on success (t=0), 1 on failure */
            return (1 & ((~t + 1) >> 31));
        }
    }
}