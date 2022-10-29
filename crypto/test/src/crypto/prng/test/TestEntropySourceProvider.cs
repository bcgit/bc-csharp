using System;

namespace Org.BouncyCastle.Crypto.Prng.Test
{
    public class TestEntropySourceProvider
        :   IEntropySourceProvider
    {
        private readonly byte[] data;
        private readonly bool isPredictionResistant;

        internal TestEntropySourceProvider(byte[] data, bool isPredictionResistant)
        {
            this.data = data;
            this.isPredictionResistant = isPredictionResistant;
        }

        public IEntropySource Get(int bitsRequired)
        {
            return new EntropySource(bitsRequired, data, isPredictionResistant);
        }

        internal class EntropySource
            :   IEntropySource
        {
            private readonly int bitsRequired;
            private readonly byte[] data;
            private readonly bool isPredictionResistant;

            int index = 0;

            internal EntropySource(int bitsRequired, byte[] data, bool isPredictionResistant)
            {
                this.bitsRequired = bitsRequired;
                this.data = data;
                this.isPredictionResistant = isPredictionResistant;
            }

            public bool IsPredictionResistant
            {
                get { return isPredictionResistant; }
            }

            public byte[] GetEntropy()
            {
                byte[] rv = new byte[bitsRequired / 8];
                Array.Copy(data, index, rv, 0, rv.Length);
                index += bitsRequired / 8;
                return rv;
            }

            // NOTE: .NET Core 3.1 has Span<T>, but is tested against our .NET Standard 2.0 assembly.
//#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
#if NET6_0_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            int IEntropySource.GetEntropy(Span<byte> output)
            {
                int length = bitsRequired / 8;
                data.AsSpan(index, length).CopyTo(output);
                index += length;
                return length;
            }
#endif

            public int EntropySize
            {
                get { return bitsRequired; }
            }
        }
    }
}
