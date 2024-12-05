using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Generators
{
    /**
     * Generator for Pbe derived keys and ivs as defined by Pkcs 12 V1.0.
     * <p>
     * The document this implementation is based on can be found at
     * <a href="http://www.rsasecurity.com/rsalabs/pkcs/pkcs-12/index.html">
     * RSA's Pkcs12 Page</a>
     * </p>
     */
    public class Pkcs12ParametersGenerator
        : PbeParametersGenerator
    {
        public const int KeyMaterial = 1;
        public const int IVMaterial = 2;
        public const int MacMaterial = 3;

        private readonly IDigest digest;
        private readonly int u;
        private readonly int v;

        /**
         * Construct a Pkcs 12 Parameters generator.
         *
         * @param digest the digest to be used as the source of derived keys.
         * @exception ArgumentException if an unknown digest is passed in.
         */
        public Pkcs12ParametersGenerator(IDigest digest)
        {
            this.digest = digest;
            this.u = digest.GetDigestSize();
            this.v = digest.GetByteLength();
        }

        /**
         * add a + b + 1, returning the result in a. The a value is treated
         * as a BigInteger of length (b.Length * 8) bits. The result is
         * modulo 2^b.Length in case of overflow.
         */
        private void Adjust(byte[] a, int aOff, byte[] b)
        {
            uint x = (uint)b[b.Length - 1] + (uint)a[aOff + b.Length - 1] + 1U;

            a[aOff + b.Length - 1] = (byte)x;
            x >>= 8;

            for (int i = b.Length - 2; i >= 0; i--)
            {
                x += (uint)b[i] + (uint)a[aOff + i];
                a[aOff + i] = (byte)x;
                x >>= 8;
            }
        }

        private byte[] GenerateDerivedKey(byte idByte, int n)
        {
            byte[] dKey = new byte[n];
            GenerateDerivedKey(idByte, dKey);
            return dKey;
        }

        /**
         * generation of a derived key ala Pkcs12 V1.0.
         */
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        private void GenerateDerivedKey(byte idByte, Span<byte> dKey)
#else
        private void GenerateDerivedKey(byte idByte, byte[] dKey)
#endif
        {
            byte[] D = new byte[v];
            Arrays.Fill(D, idByte);

            byte[] S = Array.Empty<byte>();
            if (!Arrays.IsNullOrEmpty(mSalt))
            {
                S = new byte[v * ((mSalt.Length + v - 1) / v)];
                RepeatFill(mSalt, S);
            }

            byte[] P = Array.Empty<byte>();
            if (!Arrays.IsNullOrEmpty(mPassword))
            {
                P = new byte[v * ((mPassword.Length + v - 1) / v)];
                RepeatFill(mPassword, P);
            }

            byte[] I = Arrays.Concatenate(S, P);

            byte[] A = new byte[u];
            byte[] B = new byte[v];
            int c = (dKey.Length + u - 1) / u;

            for (int i = 1; i <= c; i++)
            {
                digest.BlockUpdate(D, 0, D.Length);
                digest.BlockUpdate(I, 0, I.Length);
                digest.DoFinal(A, 0);

                for (int j = 1; j != mIterationCount; j++)
                {
                    digest.BlockUpdate(A, 0, A.Length);
                    digest.DoFinal(A, 0);
                }

                RepeatFill(A, B);

                for (int j_v = 0; j_v < I.Length; j_v += v)
                {
                    Adjust(I, j_v, B);
                }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                if (i == c)
                {
                    dKey.Slice((i - 1) * u).CopyFrom(A);
                }
                else
                {
                    A.CopyTo(dKey.Slice((i - 1) * u));
                }
#else
                if (i == c)
                {
                    Array.Copy(A, 0, dKey, (i - 1) * u, dKey.Length - ((i - 1) * u));
                }
                else
                {
                    Array.Copy(A, 0, dKey, (i - 1) * u, A.Length);
                }
#endif
            }
        }

        public override ICipherParameters GenerateDerivedParameters(string algorithm, int keySize)
        {
            keySize /= 8;

            byte[] dKey = GenerateDerivedKey(KeyMaterial, keySize);

            return ParameterUtilities.CreateKeyParameter(algorithm, dKey, 0, keySize);
        }

        public override ICipherParameters GenerateDerivedParameters(string algorithm, int keySize, int ivSize)
        {
            keySize /= 8;
            ivSize /= 8;

            byte[] dKey = GenerateDerivedKey(KeyMaterial, keySize);
            KeyParameter key = ParameterUtilities.CreateKeyParameter(algorithm, dKey, 0, keySize);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            return ParametersWithIV.Create(key, ivSize, this,
                (bytes, self) => self.GenerateDerivedKey(IVMaterial, bytes));
#else
            byte[] iv = GenerateDerivedKey(IVMaterial, ivSize);

            return new ParametersWithIV(key, iv, 0, ivSize);
#endif
        }

        /**
         * Generate a key parameter for use with a MAC derived from the password,
         * salt, and iteration count we are currently initialised with.
         *
         * @param keySize the size of the key we want (in bits)
         * @return a KeyParameter object.
         */
        public override ICipherParameters GenerateDerivedMacParameters(int keySize)
        {
            keySize /= 8;

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            return KeyParameter.Create(keySize, this,
                (bytes, self) => self.GenerateDerivedKey(MacMaterial, bytes));
#else
            byte[] dKey = GenerateDerivedKey(MacMaterial, keySize);

            return new KeyParameter(dKey, 0, keySize);
#endif
        }

        private static void RepeatFill(byte[] x, byte[] z)
        {
            int len_x = x.Length, len_z = z.Length, pos = 0;
            while (pos < len_z - len_x)
            {
                Array.Copy(x, 0, z, pos, len_x);
                pos += len_x;
            }
            Array.Copy(x, 0, z, pos, len_z - pos);
        }
    }
}
