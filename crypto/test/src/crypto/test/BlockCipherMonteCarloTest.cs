using System;

using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Crypto.Tests
{
	/**
	* a basic test that takes a cipher, key parameter, and an input
	* and output string. This test wraps the engine in a buffered block
	* cipher with padding disabled.
	*/
	public class BlockCipherMonteCarloTest
		: SimpleTest
	{
		int					id;
		int					iterations;
		IBlockCipher		engine;
		ICipherParameters	param;
		byte[]				input;
		byte[]				output;

		public BlockCipherMonteCarloTest(
			int                 id,
			int                 iterations,
			IBlockCipher         engine,
			ICipherParameters    param,
			string              input,
			string              output)
		{
			this.id = id;
			this.iterations = iterations;
			this.engine = engine;
			this.param = param;
			this.input = Hex.Decode(input);
			this.output = Hex.Decode(output);
		}

		public override string Name
		{
			get { return engine.AlgorithmName + " Monte Carlo Test " + id; }
		}

		public override void PerformTest()
		{
			BufferedBlockCipher cipher = new BufferedBlockCipher(engine);

			cipher.Init(true, param);

			byte[]  outBytes = new byte[input.Length];

			Array.Copy(input, 0, outBytes, 0, outBytes.Length);

			for (int i = 0; i != iterations; i++)
			{
				int len1 = cipher.ProcessBytes(outBytes, 0, outBytes.Length, outBytes, 0);

				cipher.DoFinal(outBytes, len1);
			}

			if (!AreEqual(outBytes, output))
			{
				Fail("failed - " + "expected " + Hex.ToHexString(output) + " got " + Hex.ToHexString(outBytes));
			}

            cipher.Init(false, param);

			for (int i = 0; i != iterations; i++)
			{
				int len1 = cipher.ProcessBytes(outBytes, 0, outBytes.Length, outBytes, 0);

				cipher.DoFinal(outBytes, len1);
			}

			if (!AreEqual(input, outBytes))
			{
				Fail("failed reversal");
			}

            // NOTE: .NET Core 3.1 has Span<T>, but is tested against our .NET Standard 2.0 assembly.
//#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
#if NET6_0_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            cipher.Init(true, param);

            Array.Copy(input, 0, outBytes, 0, outBytes.Length);

            for (int i = 0; i != iterations; i++)
            {
                int len1 = cipher.ProcessBytes(outBytes, outBytes);

				cipher.DoFinal(outBytes.AsSpan(len1));
            }

            if (!AreEqual(outBytes, output))
            {
                Fail("failed - " + "expected " + Hex.ToHexString(output) + " got " + Hex.ToHexString(outBytes));
            }

            cipher.Init(false, param);

            for (int i = 0; i != iterations; i++)
            {
                int len1 = cipher.ProcessBytes(outBytes, outBytes);

                cipher.DoFinal(outBytes.AsSpan(len1));
            }

            if (!AreEqual(input, outBytes))
            {
                Fail("failed reversal");
            }
#endif
        }
    }
}
