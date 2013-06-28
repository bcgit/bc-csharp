using System;
using System.IO;
using System.Text;

using NUnit.Framework;

using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.IO;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Crypto.Tests
{
	/// <summary>
	/// scrypt test vectors from "Stronger Key Derivation Via Sequential Memory-hard Functions" Appendix B.
	/// (http://www.tarsnap.com/scrypt/scrypt.pdf)
	/// </summary>
	[TestFixture]
	public class SCryptTest
		: SimpleTest
	{
		public override string Name
		{
			get { return "SCrypt"; }
		}

		public override void PerformTest()
		{
			using (StreamReader sr = new StreamReader(SimpleTest.GetTestDataAsStream("scrypt.TestVectors.txt")))
			{
				int count = 0;
				string line = sr.ReadLine();

				while (line != null)
				{
					++count;
					string header = line;
					StringBuilder data = new StringBuilder();

					while (!IsEndData(line = sr.ReadLine()))
					{
						data.Append(line.Replace(" ", ""));
					}

					int start = header.IndexOf('(') + 1;
					int limit = header.LastIndexOf(')');
					string argStr = header.Substring(start, limit - start);
					string[] args = argStr.Split(',');

					byte[] P = ExtractQuotedString(args[0]);
					byte[] S = ExtractQuotedString(args[1]);
					int N = ExtractInteger(args[2]);
					int r = ExtractInteger(args[3]);
					int p = ExtractInteger(args[4]);
					int dkLen = ExtractInteger(args[5]);
					byte[] expected = Hex.Decode(data.ToString());

					// This skips very expensive test case(s), remove check to re-enable
					if (N <= 16384)
					{
						byte[] result = SCrypt.Generate(P, S, N, r, p, dkLen);

						if (!AreEqual(expected, result))
						{
							Fail("Result does not match expected value in test case " + count);
						}
					}
				}
			}
		}

		private static bool IsEndData(string line)
		{
			return line == null || line.StartsWith("scrypt");
		}

		private static byte[] ExtractQuotedString(string arg)
		{
			arg = arg.Trim();
			arg = arg.Substring(1, arg.Length - 2);
			return Encoding.ASCII.GetBytes(arg);
		}

		private static int ExtractInteger(string arg)
		{
			return int.Parse(arg.Trim());
		}

		public static void Main(
			string[] args)
		{
			RunTest(new SCryptTest());
		}

		[Test]
		public void TestFunction()
		{
			string resultText = Perform().ToString();

			Assert.AreEqual(Name + ": Okay", resultText);
		}
	}
}
