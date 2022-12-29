// NOTE: .NET Core 3.1 is tested against our .NET Standard 2.0 assembly.
//#if NETCOREAPP3_0_OR_GREATER
#if NET6_0_OR_GREATER
using System;

using NUnit.Framework;

using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Crypto.Tests
{
    [TestFixture, TestOf(typeof(AesEngine_X86))]
    public class AesX86Test
        : CipherTest
    {
        private static SimpleTest[] CreateTests() => new SimpleTest[]{
            new BlockCipherVectorTest(0, new AesEngine_X86(), new KeyParameter(Hex.Decode("80000000000000000000000000000000")), "00000000000000000000000000000000", "0EDD33D3C621E546455BD8BA1418BEC8"),
            new BlockCipherVectorTest(1, new AesEngine_X86(), new KeyParameter(Hex.Decode("00000000000000000000000000000080")), "00000000000000000000000000000000", "172AEAB3D507678ECAF455C12587ADB7"),
            new BlockCipherMonteCarloTest(2, 10000, new AesEngine_X86(), new KeyParameter(Hex.Decode("00000000000000000000000000000000")), "00000000000000000000000000000000", "C34C052CC0DA8D73451AFE5F03BE297F"),
            new BlockCipherMonteCarloTest(3, 10000, new AesEngine_X86(), new KeyParameter(Hex.Decode("5F060D3716B345C253F6749ABAC10917")), "355F697E8B868B65B25A04E18D782AFA", "ACC863637868E3E068D2FD6E3508454A"),
            new BlockCipherVectorTest(4, new AesEngine_X86(), new KeyParameter(Hex.Decode("000000000000000000000000000000000000000000000000")), "80000000000000000000000000000000", "6CD02513E8D4DC986B4AFE087A60BD0C"),
            new BlockCipherMonteCarloTest(5, 10000, new AesEngine_X86(), new KeyParameter(Hex.Decode("AAFE47EE82411A2BF3F6752AE8D7831138F041560631B114")), "F3F6752AE8D7831138F041560631B114", "77BA00ED5412DFF27C8ED91F3C376172"),
            new BlockCipherVectorTest(6, new AesEngine_X86(), new KeyParameter(Hex.Decode("0000000000000000000000000000000000000000000000000000000000000000")), "80000000000000000000000000000000", "DDC6BF790C15760D8D9AEB6F9A75FD4E"),
            new BlockCipherMonteCarloTest(7, 10000, new AesEngine_X86(), new KeyParameter(Hex.Decode("28E79E2AFC5F7745FCCABE2F6257C2EF4C4EDFB37324814ED4137C288711A386")), "C737317FE0846F132B23C8C2A672CE22", "E58B82BFBA53C0040DC610C642121168"),
            new BlockCipherVectorTest(8, new AesEngine_X86(), new KeyParameter(Hex.Decode("80000000000000000000000000000000")), "00000000000000000000000000000000", "0EDD33D3C621E546455BD8BA1418BEC8"),
            new BlockCipherVectorTest(9, new AesEngine_X86(), new KeyParameter(Hex.Decode("00000000000000000000000000000080")), "00000000000000000000000000000000", "172AEAB3D507678ECAF455C12587ADB7"),
            new BlockCipherMonteCarloTest(10, 10000, new AesEngine_X86(), new KeyParameter(Hex.Decode("00000000000000000000000000000000")), "00000000000000000000000000000000", "C34C052CC0DA8D73451AFE5F03BE297F"),
            new BlockCipherMonteCarloTest(11, 10000, new AesEngine_X86(), new KeyParameter(Hex.Decode("5F060D3716B345C253F6749ABAC10917")), "355F697E8B868B65B25A04E18D782AFA", "ACC863637868E3E068D2FD6E3508454A"),
            new BlockCipherVectorTest(12, new AesEngine_X86(), new KeyParameter(Hex.Decode("000000000000000000000000000000000000000000000000")), "80000000000000000000000000000000", "6CD02513E8D4DC986B4AFE087A60BD0C"),
            new BlockCipherMonteCarloTest(13, 10000, new AesEngine_X86(), new KeyParameter(Hex.Decode("AAFE47EE82411A2BF3F6752AE8D7831138F041560631B114")), "F3F6752AE8D7831138F041560631B114", "77BA00ED5412DFF27C8ED91F3C376172"),
            new BlockCipherVectorTest(14, new AesEngine_X86(), new KeyParameter(Hex.Decode("0000000000000000000000000000000000000000000000000000000000000000")), "80000000000000000000000000000000", "DDC6BF790C15760D8D9AEB6F9A75FD4E"),
            new BlockCipherMonteCarloTest(15, 10000, new AesEngine_X86(), new KeyParameter(Hex.Decode("28E79E2AFC5F7745FCCABE2F6257C2EF4C4EDFB37324814ED4137C288711A386")), "C737317FE0846F132B23C8C2A672CE22", "E58B82BFBA53C0040DC610C642121168"),
            new BlockCipherVectorTest(16, new AesEngine_X86(), new KeyParameter(Hex.Decode("80000000000000000000000000000000")), "00000000000000000000000000000000", "0EDD33D3C621E546455BD8BA1418BEC8"),
            new BlockCipherVectorTest(17, new AesEngine_X86(), new KeyParameter(Hex.Decode("00000000000000000000000000000080")), "00000000000000000000000000000000", "172AEAB3D507678ECAF455C12587ADB7"),
            new BlockCipherMonteCarloTest(18, 10000, new AesEngine_X86(), new KeyParameter(Hex.Decode("00000000000000000000000000000000")), "00000000000000000000000000000000", "C34C052CC0DA8D73451AFE5F03BE297F"),
            new BlockCipherMonteCarloTest(19, 10000, new AesEngine_X86(), new KeyParameter(Hex.Decode("5F060D3716B345C253F6749ABAC10917")), "355F697E8B868B65B25A04E18D782AFA", "ACC863637868E3E068D2FD6E3508454A"),
            new BlockCipherVectorTest(20, new AesEngine_X86(), new KeyParameter(Hex.Decode("000000000000000000000000000000000000000000000000")), "80000000000000000000000000000000", "6CD02513E8D4DC986B4AFE087A60BD0C"),
            new BlockCipherMonteCarloTest(21, 10000, new AesEngine_X86(), new KeyParameter(Hex.Decode("AAFE47EE82411A2BF3F6752AE8D7831138F041560631B114")), "F3F6752AE8D7831138F041560631B114", "77BA00ED5412DFF27C8ED91F3C376172"),
            new BlockCipherVectorTest(22, new AesEngine_X86(), new KeyParameter(Hex.Decode("0000000000000000000000000000000000000000000000000000000000000000")), "80000000000000000000000000000000", "DDC6BF790C15760D8D9AEB6F9A75FD4E"),
            new BlockCipherMonteCarloTest(23, 10000, new AesEngine_X86(), new KeyParameter(Hex.Decode("28E79E2AFC5F7745FCCABE2F6257C2EF4C4EDFB37324814ED4137C288711A386")), "C737317FE0846F132B23C8C2A672CE22", "E58B82BFBA53C0040DC610C642121168")
        };

        private static readonly SecureRandom Random = new SecureRandom();

        [OneTimeSetUp]
        public static void OneTimeSetup()
        {
            if (!AesEngine_X86.IsSupported)
            {
                Assert.Ignore();
            }
        }

        public override string Name => "AesX86";

        public AesX86Test()
            : base()
        {
        }

        public override ITestResult Perform()
        {
            if (AesEngine_X86.IsSupported)
            {
                ITestResult result = base.Perform();
                if (!result.IsSuccessful())
                    return result;
            }

            return new SimpleTestResult(true, Name + ": Okay");
        }

        public override void PerformTest()
        {
            RunTests(CreateTests());
            RunEngineChecks(new AesEngine_X86(), new KeyParameter(new byte[16]));
        }

        [Test]
        public void TestFunction()
        {
            string resultText = Perform().ToString();

            Assert.AreEqual(Name + ": Okay", resultText);
        }

        [Test]
        public void TestFourBlocksDecrypt128()
        {
            ImplTestFourBlocks(false, 128);
        }

        [Test]
        public void TestFourBlocksDecrypt192()
        {
            ImplTestFourBlocks(false, 192);
        }

        [Test]
        public void TestFourBlocksDecrypt256()
        {
            ImplTestFourBlocks(false, 256);
        }

        [Test]
        public void TestFourBlocksEncrypt128()
        {
            ImplTestFourBlocks(true, 128);
        }

        [Test]
        public void TestFourBlocksEncrypt192()
        {
            ImplTestFourBlocks(true, 192);
        }

        [Test]
        public void TestFourBlocksEncrypt256()
        {
            ImplTestFourBlocks(true, 256);
        }

        private static void ImplTestFourBlocks(bool forEncryption, int keySize)
        {
            Span<byte> key = stackalloc byte[keySize / 8];
            Span<byte> data = stackalloc byte[64];
            Span<byte> fourBlockOutput = stackalloc byte[64];
            Span<byte> singleBlockOutput = stackalloc byte[64];

            for (int i = 0; i < 100; ++i)
            {
                Random.NextBytes(key);
                Random.NextBytes(data);

                var aes = new AesEngine_X86();
                aes.Init(forEncryption, new KeyParameter(key));

                aes.ProcessFourBlocks(data, fourBlockOutput);

                for (int j = 0; j < 64; j += 16)
                {
                    aes.ProcessBlock(data[j..], singleBlockOutput[j..]);
                }

                Assert.IsTrue(fourBlockOutput.SequenceEqual(singleBlockOutput));
            }
        }
    }
}
#endif
