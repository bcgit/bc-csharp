using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Parameters
{
    /// <summary>Parameters for the key derivation function in feedback mode (NIST SP 800-108).</summary>
    public class KdfFeedbackParameters : IDerivationParameters
    {
        // could be any valid value, using 32, don't know why
        private static readonly int UNUSED_R = -1;

        private readonly byte[] ki;
        private readonly byte[] iv;
        private readonly bool useCounter;
        private readonly int r;
        private readonly byte[] fixedInputData;

        private KdfFeedbackParameters(byte[] ki, byte[] iv, byte[] fixedInputData, int r, bool useCounter)
        {
            if (ki == null)
            {
                throw new ArgumentException("A KDF requires Ki (a seed) as input");
            }

            this.ki = Arrays.Clone(ki);

            if (fixedInputData == null)
            {
                this.fixedInputData = new byte[0];
            }
            else
            {
                this.fixedInputData = Arrays.Clone(fixedInputData);
            }

            this.r = r;

            if (iv == null)
            {
                this.iv = new byte[0];
            }
            else
            {
                this.iv = Arrays.Clone(iv);
            }

            this.useCounter = useCounter;
        }

        /// <summary>Create parameters for the feedback mode of SP 800-108, with a counter.</summary>
        /// <param name="ki">The key derivation key.</param>
        /// <param name="iv">The initialization vector.</param>
        /// <param name="fixedInputData">The fixed input data.</param>
        /// <param name="r">The length of the counter in bits (8, 16, 24 or 32).</param>
        /// <returns>The parameters.</returns>
        public static KdfFeedbackParameters CreateWithCounter(
            byte[] ki, byte[] iv, byte[] fixedInputData, int r)
        {
            if (r != 8 && r != 16 && r != 24 && r != 32)
            {
                throw new ArgumentException("Length of counter should be 8, 16, 24 or 32");
            }

            return new KdfFeedbackParameters(ki, iv, fixedInputData, r, true);
        }

        /// <summary>Create parameters for the feedback mode of SP 800-108, without a counter.</summary>
        /// <param name="ki">The key derivation key.</param>
        /// <param name="iv">The initialization vector.</param>
        /// <param name="fixedInputData">The fixed input data.</param>
        /// <returns>The parameters.</returns>
        public static KdfFeedbackParameters CreateWithoutCounter(
            byte[] ki, byte[] iv, byte[] fixedInputData)
        {
            return new KdfFeedbackParameters(ki, iv, fixedInputData, UNUSED_R, false);
        }

        /// <summary>Gets the ki.</summary>
        public byte[] Ki
        {
            get { return Arrays.Clone(ki); }
        }

        /// <summary>Gets the iv.</summary>
        public byte[] Iv
        {
            get { return Arrays.Clone(iv); }
        }

        /// <summary>Gets the use counter.</summary>
        public bool UseCounter
        {
            get { return useCounter; }
        }

        /// <summary>Gets the r.</summary>
        public int R
        {
            get { return r; }
        }

        /// <summary>Gets the fixed input data.</summary>
        public byte[] FixedInputData
        {
            get { return Arrays.Clone(fixedInputData); }
        }
    }
}