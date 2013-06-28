using System;
using System.Text;

using NUnit.Framework;

using Org.BouncyCastle.Asn1.Iana;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Tests
{
    /// <remarks>HMAC tester</remarks>
    [TestFixture]
    public class HMacTest
        : SimpleTest
    {
        private static byte[] keyBytes = Hex.Decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        private static byte[] message = Encoding.ASCII.GetBytes("Hi There");
        private static byte[] output1 = Hex.Decode("b617318655057264e28bc0b6fb378c8ef146be00");
        private static byte[] outputMD5 = Hex.Decode("5ccec34ea9656392457fa1ac27f08fbc");
        private static byte[] outputMD2 = Hex.Decode("dc1923ef5f161d35bef839ca8c807808");
        private static byte[] outputMD4 = Hex.Decode("5570ce964ba8c11756cdc3970278ff5a");
        private static byte[] output224 = Hex.Decode("896fb1128abbdf196832107cd49df33f47b4b1169912ba4f53684b22");
        private static byte[] output256 = Hex.Decode("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
        private static byte[] output384 = Hex.Decode("afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6");
        private static byte[] output512 = Hex.Decode("87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854");
        private static byte[] output512_224 = Hex.Decode("b244ba01307c0e7a8ccaad13b1067a4cf6b961fe0c6a20bda3d92039");
        private static byte[] output512_256 = Hex.Decode("9f9126c3d9c3c330d760425ca8a217e31feae31bfe70196ff81642b868402eab");
        private static byte[] outputRipeMD128 = Hex.Decode("fda5717fb7e20cf05d30bb286a44b05d");
        private static byte[] outputRipeMD160 = Hex.Decode("24cb4bd67d20fc1a5d2ed7732dcc39377f0a5668");
        private static byte[] outputTiger = Hex.Decode("1d7a658c75f8f004916e7b07e2a2e10aec7de2ae124d3647");
        private static byte[] outputOld384 = Hex.Decode("0a046aaa0255e432912228f8ccda437c8a8363fb160afb0570ab5b1fd5ddc20eb1888b9ed4e5b6cb5bc034cd9ef70e40");
        private static byte[] outputOld512 = Hex.Decode("9656975ee5de55e75f2976ecce9a04501060b9dc22a6eda2eaef638966280182477fe09f080b2bf564649cad42af8607a2bd8d02979df3a980f15e2326a0a22a");

        public void doTestHMac(
            string  hmacName,
            byte[]  output)
        {
            KeyParameter key = new KeyParameter(keyBytes); //, hmacName);

            IMac mac = MacUtilities.GetMac(hmacName);

            mac.Init(key);

            mac.Reset();

            mac.BlockUpdate(message, 0, message.Length);

//			byte[] outBytes = mac.DoFinal();
            byte[] outBytes = new byte[mac.GetMacSize()];
            mac.DoFinal(outBytes, 0);

            if (!AreEqual(outBytes, output))
            {
                Fail("Failed - expected "
                    + Hex.ToHexString(output) + " got "
                    + Hex.ToHexString(outBytes));
            }

            // no key generator for the old algorithms
            if (hmacName.StartsWith("Old"))
            {
                return;
            }

            CipherKeyGenerator kGen = GeneratorUtilities.GetKeyGenerator(hmacName);

            mac.Init(new KeyParameter(kGen.GenerateKey())); // hmacName

            mac.BlockUpdate(message, 0, message.Length);

//			outBytes = mac.DoFinal();
            outBytes = new byte[mac.GetMacSize()];
            mac.DoFinal(outBytes, 0);
        }

        private void doTestExceptions()
        {
            IMac mac = MacUtilities.GetMac("HmacSHA1");

            byte [] b = {(byte)1, (byte)2, (byte)3, (byte)4, (byte)5};
//			KeyParameter sks = new KeyParameter(b); //, "HmacSHA1");
//			RC5ParameterSpec algPS = new RC5ParameterSpec(100, 100, 100);
            RC5Parameters rc5Parameters = new RC5Parameters(b, 100);

            try
            {
//				mac.Init(sks, algPS);
                mac.Init(rc5Parameters);
            }
//			catch (InvalidAlgorithmParameterException e)
            catch (Exception)
            {
                // ignore okay
            }

            try
            {
                mac.Init(null); //, null);
            }
//			catch (InvalidKeyException)
//			{
//				// ignore okay
//			}
//			catch (InvalidAlgorithmParameterException e)
            catch (Exception)
            {
                // ignore okay
            }

//			try
//			{
//				mac.Init(null);
//			}
//			catch (InvalidKeyException)
//			{
//				// ignore okay
//			}
        }

        public override void PerformTest()
        {
            doTestHMac("HMac-SHA1", output1);
            doTestHMac("HMac-MD5", outputMD5);
            doTestHMac("HMac-MD4", outputMD4);
            doTestHMac("HMac-MD2", outputMD2);
            doTestHMac("HMac-SHA224", output224);
            doTestHMac("HMac-SHA256", output256);
            doTestHMac("HMac-SHA384", output384);
            doTestHMac("HMac-SHA512", output512);
            doTestHMac("HMac-SHA512/224", output512_224);
            doTestHMac("HMac-SHA512/256", output512_256);
            doTestHMac("HMac-RIPEMD128", outputRipeMD128);
            doTestHMac("HMac-RIPEMD160", outputRipeMD160);
            doTestHMac("HMac-TIGER", outputTiger);

            doTestHMac("HMac/SHA1", output1);
            doTestHMac("HMac/MD5", outputMD5);
            doTestHMac("HMac/MD4", outputMD4);
            doTestHMac("HMac/MD2", outputMD2);
            doTestHMac("HMac/SHA224", output224);
            doTestHMac("HMac/SHA256", output256);
            doTestHMac("HMac/SHA384", output384);
            doTestHMac("HMac/SHA512", output512);
            doTestHMac("HMac/RIPEMD128", outputRipeMD128);
            doTestHMac("HMac/RIPEMD160", outputRipeMD160);
            doTestHMac("HMac/TIGER", outputTiger);

            doTestHMac(PkcsObjectIdentifiers.IdHmacWithSha1.Id, output1);
            doTestHMac(PkcsObjectIdentifiers.IdHmacWithSha224.Id, output224);
            doTestHMac(PkcsObjectIdentifiers.IdHmacWithSha256.Id, output256);
            doTestHMac(PkcsObjectIdentifiers.IdHmacWithSha384.Id, output384);
            doTestHMac(PkcsObjectIdentifiers.IdHmacWithSha512.Id, output512);
            doTestHMac(IanaObjectIdentifiers.HmacSha1.Id, output1);
            doTestHMac(IanaObjectIdentifiers.HmacMD5.Id, outputMD5);
            doTestHMac(IanaObjectIdentifiers.HmacRipeMD160.Id, outputRipeMD160);
            doTestHMac(IanaObjectIdentifiers.HmacTiger.Id, outputTiger);

//			// test for compatibility with broken HMac.
//			doTestHMac("OldHMacSHA384", outputOld384);
//			doTestHMac("OldHMacSHA512", outputOld512);

            doTestExceptions();
        }

        public override string Name
        {
            get { return "HMac"; }
        }

        public static void Main(
            string[] args)
        {
            RunTest(new HMacTest());
        }

        [Test]
        public void TestFunction()
        {
            string resultText = Perform().ToString();

            Assert.AreEqual(Name + ": Okay", resultText);
        }
    }
}
