using System.Collections.Generic;
using System.IO;

using NUnit.Framework;

using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Crypto.Tests
{
    [TestFixture]
    public class SparkleTest
    {
        [Test, Explicit]
        public void BenchDigest256()
        {
            ImplBenchDigest(SparkleDigest.SparkleParameters.ESCH256);
        }

        [Test, Explicit]
        public void BenchDigest384()
        {
            ImplBenchDigest(SparkleDigest.SparkleParameters.ESCH384);
        }

        [Test]
        public void TestExceptionsDigest256()
        {
            ImplTestExceptionsDigest(SparkleDigest.SparkleParameters.ESCH256, 32);
        }

        [Test]
        public void TestExceptionsDigest384()
        {
            ImplTestExceptionsDigest(SparkleDigest.SparkleParameters.ESCH384, 48);
        }

        [Test]
        public void TestVectorsDigest256()
        {
            ImplTestVectorsDigest(SparkleDigest.SparkleParameters.ESCH256, "256");
        }

        [Test]
        public void TestVectorsDigest384()
        {
            ImplTestVectorsDigest(SparkleDigest.SparkleParameters.ESCH384, "384");
        }

        private static void ImplBenchDigest(SparkleDigest.SparkleParameters sparkleParameters)
        {
            var digest = new SparkleDigest(sparkleParameters);

            byte[] data = new byte[1024];
            for (int i = 0; i < 1024; ++i)
            {
                for (int j = 0; j < 1024; ++j)
                {
#if NET6_0_OR_GREATER
                    digest.BlockUpdate(data);
#else
                    digest.BlockUpdate(data, 0, 1024);
#endif
                }

                digest.DoFinal(data, 0);
            }
        }

        private static void ImplTestVectorsDigest(SparkleDigest.SparkleParameters sparkleParameters, string filename)
        {
            SparkleDigest sparkle = new SparkleDigest(sparkleParameters);
            var map = new Dictionary<string, string>();
            using (var src = new StreamReader(
                SimpleTest.GetTestDataAsStream("crypto.sparkle.LWC_HASH_KAT_" + filename + ".txt")))
            {
                string line;
                while ((line = src.ReadLine()) != null)
                {
                    int a = line.IndexOf('=');
                    if (a < 0)
                    {
                        byte[] ptByte = Hex.Decode(map["Msg"]);
                        byte[] expected = Hex.Decode(map["MD"]);
                        map.Clear();

                        sparkle.BlockUpdate(ptByte, 0, ptByte.Length);
                        byte[] hash = new byte[sparkle.GetDigestSize()];
                        sparkle.DoFinal(hash, 0);
                        Assert.IsTrue(Arrays.AreEqual(expected, hash));
                    }
                    else
                    {
                        map[line.Substring(0, a).Trim()] = line.Substring(a + 1).Trim();
                    }
                }
            }
        }

        private static void ImplTestExceptionsDigest(SparkleDigest.SparkleParameters sparkleParameters, int digestSize)
        {
            var sparkle = new SparkleDigest(sparkleParameters);

            Assert.AreEqual(digestSize, sparkle.GetDigestSize(),
                sparkle.AlgorithmName + ": GetDigestSize() is not correct");

            try
            {
                sparkle.BlockUpdate(new byte[1], 1, 1);
                Assert.Fail(sparkle.AlgorithmName + ": input for BlockUpdate is too short");
            }
            catch (DataLengthException)
            {
                //expected
            }
            try
            {
                sparkle.DoFinal(new byte[digestSize - 1], 2);
                Assert.Fail(sparkle.AlgorithmName + ": output for Dofinal is too short");
            }
            catch (DataLengthException)
            {
                //expected
            }
        }
    }
}
