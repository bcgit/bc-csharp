using System;

using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Crypto.Generators
{
    public sealed class KdfFeedbackBytesGenerator
        : IMacDerivationFunction
    {
        // please refer to the standard for the meaning of the variable names
        // all field lengths are in bytes, not in bits as specified by the standard

        // fields set by the constructor
        private readonly IMac prf;
        private readonly int h;

        // fields set by init
        private byte[] fixedInputData;
        private int maxSizeExcl;
        // ios is i defined as an octet string (the binary representation)
        private byte[] ios;
        private byte[] iv;
        private bool useCounter;

        // operational
        private int generatedBytes;
        // k is used as buffer for all K(i) values
        private byte[] k;

        public KdfFeedbackBytesGenerator(IMac prf)
        {
            this.prf = prf;
            this.h = prf.GetMacSize();
            this.k = new byte[h];
        }

        public void Init(IDerivationParameters parameters)
        {
            if (!(parameters is KdfFeedbackParameters feedbackParams))
                throw new ArgumentException("Wrong type of arguments given");

            // --- init mac based PRF ---

            this.prf.Init(new KeyParameter(feedbackParams.Ki));

            // --- set arguments ---

            this.fixedInputData = feedbackParams.FixedInputData;

            int r = feedbackParams.R;
            this.ios = new byte[r / 8];

            if (feedbackParams.UseCounter)
            {
                // this is more conservative than the spec
                BigInteger maxSize = BigInteger.One.ShiftLeft(r).Multiply(BigInteger.ValueOf(h));
                this.maxSizeExcl = maxSize.BitLength > 31 ? int.MaxValue : maxSize.IntValueExact;
            }
            else
            {
                this.maxSizeExcl = int.MaxValue;
            }

            this.iv = feedbackParams.Iv;
            this.useCounter = feedbackParams.UseCounter;

            // --- set operational state ---

            generatedBytes = 0;
        }

        public IDigest Digest
        {
            get { return (prf as HMac)?.GetUnderlyingDigest(); }
        }

        public int GenerateBytes(byte[] output, int outOff, int length)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            return GenerateBytes(output.AsSpan(outOff, length));
#else
            if (generatedBytes >= maxSizeExcl - length)
                throw new DataLengthException("Current KDFCTR may only be used for " + maxSizeExcl + " bytes");

            int toGenerate = length;
            int posInK = generatedBytes % h;
            if (posInK != 0)
            {
                // copy what is left in the currentT (1..hash
                int toCopy = System.Math.Min(h - posInK, toGenerate);
                Array.Copy(k, posInK, output, outOff, toCopy);
                generatedBytes += toCopy;
                toGenerate -= toCopy;
                outOff += toCopy;
            }

            while (toGenerate > 0)
            {
                GenerateNext();
                int toCopy = System.Math.Min(h, toGenerate);
                Array.Copy(k, 0, output, outOff, toCopy);
                generatedBytes += toCopy;
                toGenerate -= toCopy;
                outOff += toCopy;
            }

            return length;
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public int GenerateBytes(Span<byte> output)
        {
            int length = output.Length;
            if (generatedBytes >= maxSizeExcl - length)
                throw new DataLengthException("Current KDFCTR may only be used for " + maxSizeExcl + " bytes");

            int posInK = generatedBytes % h;
            if (posInK != 0)
            {
                // copy what is left in the currentT (1..hash
                int toCopy = System.Math.Min(h - posInK, output.Length);
                k.AsSpan(posInK, toCopy).CopyTo(output);
                generatedBytes += toCopy;
                output = output[toCopy..];
            }

            while (!output.IsEmpty)
            {
                GenerateNext();
                int toCopy = System.Math.Min(h, output.Length);
                k.AsSpan(0, toCopy).CopyTo(output);
                generatedBytes += toCopy;
                output = output[toCopy..];
            }

            return length;
        }
#endif

        private void GenerateNext()
        {
            // TODO enable IV
            if (generatedBytes == 0)
            {
                prf.BlockUpdate(iv, 0, iv.Length);
            }
            else
            {
                prf.BlockUpdate(k, 0, k.Length);
            }

            if (useCounter)
            {
                int i = generatedBytes / h + 1;

                // encode i into counter buffer
                switch (ios.Length)
                {
                case 4:
                    ios[0] = (byte)(i >> 24);
                    // fall through
                    goto case 3;
                case 3:
                    ios[ios.Length - 3] = (byte)(i >> 16);
                    // fall through
                    goto case 2;
                case 2:
                    ios[ios.Length - 2] = (byte)(i >> 8);
                    // fall through
                    goto case 1;
                case 1:
                    ios[ios.Length - 1] = (byte)i;
                    break;
                default:
                    throw new InvalidOperationException("Unsupported size of counter i");
                }
                prf.BlockUpdate(ios, 0, ios.Length);
            }

            prf.BlockUpdate(fixedInputData, 0, fixedInputData.Length);
            prf.DoFinal(k, 0);
        }

        public IMac Mac => prf;
    }
}
