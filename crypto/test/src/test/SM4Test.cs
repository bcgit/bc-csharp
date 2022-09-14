using System;
using System.IO;

using NUnit.Framework;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.IO;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Encoders;

namespace Org.BouncyCastle.Tests
{
    /**
     * basic test class for SM4
     */
	[TestFixture]
    public class SM4Test
        : BaseBlockCipherTest
    {
        internal static readonly string[] cipherTests =
        {
            "128",
            "0123456789abcdeffedcba9876543210",
            "0123456789abcdeffedcba9876543210",
            "681edf34d206965e86b3e94f536e4246"
        };

        public SM4Test()
            : base("SM4")
        {
        }

        public void DoTest(
            int         strength,
            byte[]      keyBytes,
            byte[]      input,
            byte[]      output)
        {
            KeyParameter key = ParameterUtilities.CreateKeyParameter("SM4", keyBytes);

            IBufferedCipher inCipher = CipherUtilities.GetCipher("SM4/ECB/NoPadding");
            IBufferedCipher outCipher = CipherUtilities.GetCipher("SM4/ECB/NoPadding");

            try
            {
                outCipher.Init(true, key);
            }
            catch (Exception e)
            {
                Fail("SM4 failed initialisation - " + e, e);
            }

            try
            {
                inCipher.Init(false, key);
            }
            catch (Exception e)
            {
                Fail("SM4 failed initialisation - " + e, e);
            }

            //
            // encryption pass
            //
			MemoryStream bOut = new MemoryStream();

			CipherStream cOut = new CipherStream(bOut, null, outCipher);

            try
            {
                for (int i = 0; i != input.Length / 2; i++)
                {
                    cOut.WriteByte(input[i]);
                }
                cOut.Write(input, input.Length / 2, input.Length - input.Length / 2);
                cOut.Close();
            }
            catch (IOException e)
            {
                Fail("SM4 failed encryption - " + e, e);
            }

            byte[] bytes = bOut.ToArray();

            if (!AreEqual(bytes, output))
            {
				Fail("SM4 failed encryption - expected "
					+ Hex.ToHexString(output) + " got "
					+ Hex.ToHexString(bytes));
            }

            //
            // decryption pass
            //
			MemoryStream bIn = new MemoryStream(bytes, false);

			CipherStream cIn = new CipherStream(bIn, inCipher, null);

            try
            {
//				DataInputStream dIn = new DataInputStream(cIn);
				BinaryReader dIn = new BinaryReader(cIn);

				bytes = new byte[input.Length];

				for (int i = 0; i != input.Length / 2; i++)
				{
//					bytes[i] = (byte)dIn.read();
					bytes[i] = dIn.ReadByte();
				}

				int remaining = bytes.Length - input.Length / 2;
//				dIn.readFully(bytes, input.Length / 2, remaining);
				byte[] extra = dIn.ReadBytes(remaining);
				if (extra.Length < remaining)
					throw new EndOfStreamException();
				extra.CopyTo(bytes, input.Length / 2);
            }
            catch (Exception e)
            {
                Fail("SM4 failed encryption - " + e, e);
            }

            if (!AreEqual(bytes, input))
            {
				Fail("SM4 failed decryption - expected "
					+ Hex.ToHexString(input) + " got "
					+ Hex.ToHexString(bytes));
            }
        }

        public override void PerformTest()
        {
            for (int i = 0; i != cipherTests.Length; i += 4)
            {
                DoTest(int.Parse(cipherTests[i]),
                    Hex.Decode(cipherTests[i + 1]),
                    Hex.Decode(cipherTests[i + 2]),
                    Hex.Decode(cipherTests[i + 3]));
            }
        }
    }
}
