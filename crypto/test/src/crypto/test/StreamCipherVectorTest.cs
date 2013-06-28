using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Test;
using Org.BouncyCastle.Utilities.Encoders;

namespace Org.BouncyCastle.Crypto.Tests
{
    /**
     * a basic test that takes a stream cipher, key parameter, and an input
     * and output string.
     */
    public class StreamCipherVectorTest: ITest
    {
        int                 id;
        IStreamCipher       cipher;
        ICipherParameters    param;
        byte[]              input;
        byte[]              output;

        public StreamCipherVectorTest(
            int                 id,
            IStreamCipher       cipher,
            ICipherParameters    param,
            string              input,
            string              output)
        {
            this.id = id;
            this.cipher = cipher;
            this.param = param;
            this.input = Hex.Decode(input);
            this.output = Hex.Decode(output);
        }

		public string Name
		{
			get { return cipher.AlgorithmName + " Vector Test " + id; }
		}

		public ITestResult Perform()
        {
            cipher.Init(true, param);

            byte[] outBytes = new byte[input.Length];

            cipher.ProcessBytes(input, 0, input.Length, outBytes, 0);

            if (!Arrays.AreEqual(outBytes, output))
            {
                return new SimpleTestResult(false, Name + ": failed - "
					+ "expected " + Hex.ToHexString(output)
					+ " got " + Hex.ToHexString(outBytes));
            }

            cipher.Init(false, param);

            cipher.ProcessBytes(output, 0, output.Length, outBytes, 0);

            if (!Arrays.AreEqual(input, outBytes))
            {
                return new SimpleTestResult(false, Name + ": failed reversal");
            }

            return new SimpleTestResult(true, Name + ": OKAY");
        }
    }
}
