using System;

using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Macs
{
    public class KMac
        : IMac, IXof
    {
        private static readonly byte[] padding = new byte[100];

        private readonly CShakeDigest cshake;
        private readonly int bitLength;
        private readonly int outputLength;

        private byte[] key;
        private bool initialised;
        private bool firstOutput;

        public KMac(int bitLength, byte[] S)
        {
            this.cshake = new CShakeDigest(bitLength, Strings.ToAsciiByteArray("KMAC"), S);
            this.bitLength = bitLength;
            this.outputLength = bitLength * 2 / 8;
        }

        public string AlgorithmName
        {
            get { return "KMAC" + cshake.AlgorithmName.Substring(6); }
        }

        public void BlockUpdate(byte[] input, int inOff, int len)
        {
            if (!initialised)
                throw new InvalidOperationException("KMAC not initialized");

            cshake.BlockUpdate(input, inOff, len);
        }

        public int DoFinal(byte[] output, int outOff)
        {
            if (firstOutput)
            {
                if (!initialised)
                    throw new InvalidOperationException("KMAC not initialized");

                byte[] encOut = XofUtilities.RightEncode(GetMacSize() * 8);

                cshake.BlockUpdate(encOut, 0, encOut.Length);
            }

            int rv = cshake.DoFinal(output, outOff, GetMacSize());

            Reset();

            return rv;
        }

        public int DoFinal(byte[] output, int outOff, int outLen)
        {
            if (firstOutput)
            {
                if (!initialised)
                    throw new InvalidOperationException("KMAC not initialized");

                byte[] encOut = XofUtilities.RightEncode(outLen * 8);

                cshake.BlockUpdate(encOut, 0, encOut.Length);
            }

            int rv = cshake.DoFinal(output, outOff, outLen);

            Reset();

            return rv;
        }

        public int DoOutput(byte[] output, int outOff, int outLen)
        {
            if (firstOutput)
            {
                if (!initialised)
                    throw new InvalidOperationException("KMAC not initialized");

                byte[] encOut = XofUtilities.RightEncode(0);

                cshake.BlockUpdate(encOut, 0, encOut.Length);

                firstOutput = false;
            }

            return cshake.DoOutput(output, outOff, outLen);
        }

        public int GetByteLength()
        {
            return cshake.GetByteLength();
        }

        public int GetDigestSize()
        {
            return outputLength;
        }

        public int GetMacSize()
        {
            return outputLength;
        }

        public void Init(ICipherParameters parameters)
        {
            KeyParameter kParam = (KeyParameter)parameters;
            this.key = Arrays.Clone(kParam.GetKey());
            this.initialised = true;
            Reset();
        }

        public void Reset()
        {
            cshake.Reset();

            if (key != null)
            {
                if (bitLength == 128)
                {
                    bytePad(key, 168);
                }
                else
                {
                    bytePad(key, 136);
                }
            }

            firstOutput = true;
        }

        private void bytePad(byte[] X, int w)
        {
            byte[] bytes = XofUtilities.LeftEncode(w);
            BlockUpdate(bytes, 0, bytes.Length);
            byte[] encX = encode(X);
            BlockUpdate(encX, 0, encX.Length);

            int required = w - ((bytes.Length + encX.Length) % w);

            if (required > 0 && required != w)
            {
                while (required > padding.Length)
                {
                    BlockUpdate(padding, 0, padding.Length);
                    required -= padding.Length;
                }

                BlockUpdate(padding, 0, required);
            }
        }

        private static byte[] encode(byte[] X)
        {
            return Arrays.Concatenate(XofUtilities.LeftEncode(X.Length * 8), X);
        }

        public void Update(byte input)
        {
            if (!initialised)
                throw new InvalidOperationException("KMAC not initialized");

            cshake.Update(input);
        }
    }
}
