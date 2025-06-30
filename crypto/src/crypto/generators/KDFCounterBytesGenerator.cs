using System;

using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Generators
{
    public sealed class KdfCounterBytesGenerator
        : IMacDerivationFunction
    {
        private readonly IMac prf;
        private readonly int h;

        private byte[] fixedInputDataCtrPrefix;
        private byte[] fixedInputData_afterCtr;
        private int maxSizeExcl;
        // ios is i defined as an octet string (the binary representation)
        private byte[] ios;

        // operational
        private int generatedBytes;
        // k is used as buffer for all K(i) values
        private byte[] k;

        public KdfCounterBytesGenerator(IMac prf)
        {
            this.prf = prf;
            this.h = prf.GetMacSize();
            this.k = new byte[h];
        }

        public void Init(IDerivationParameters param)
        {
            if (!(param is KdfCounterParameters kdfParams))
                throw new ArgumentException("Wrong type of arguments given");

            // --- init mac based PRF ---

            this.prf.Init(new KeyParameter(kdfParams.Ki));

            // --- set arguments ---

            this.fixedInputDataCtrPrefix = kdfParams.FixedInputDataCounterPrefix;
            this.fixedInputData_afterCtr = kdfParams.FixedInputDataCounterSuffix;

            int r = kdfParams.R;
            this.ios = new byte[r / 8];

            this.maxSizeExcl = r >= Integers.NumberOfLeadingZeros(h) ? int.MaxValue : h << r;

            // --- set operational state ---

            generatedBytes = 0;
        }

        public IMac Mac => prf;

        public IDigest Digest => (prf as HMac)?.GetUnderlyingDigest();

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

            // special case for K(0): K(0) is empty, so no update
            prf.BlockUpdate(fixedInputDataCtrPrefix, 0, fixedInputDataCtrPrefix.Length);
            prf.BlockUpdate(ios, 0, ios.Length);
            prf.BlockUpdate(fixedInputData_afterCtr, 0, fixedInputData_afterCtr.Length);
            prf.DoFinal(k, 0);
        }
    }
}
