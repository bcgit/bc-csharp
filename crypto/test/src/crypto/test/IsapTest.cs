using System;
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
    public class IsapTest
    {
        [Test, Explicit]
        public void BenchDigest()
        {
            var isap = new IsapDigest();

            byte[] data = new byte[1024];
            for (int i = 0; i < 1024; ++i)
            {
                for (int j = 0; j < 1024; ++j)
                {
                    // NOTE: .NET Core 3.1 has Span<T>, but is tested against our .NET Standard 2.0 assembly.
//#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
#if NET6_0_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                    isap.BlockUpdate(data);
#else
                    isap.BlockUpdate(data, 0, 1024);
#endif
                }

                // NOTE: .NET Core 3.1 has Span<T>, but is tested against our .NET Standard 2.0 assembly.
//#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
#if NET6_0_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                isap.DoFinal(data);
#else
                isap.DoFinal(data, 0);
#endif
            }
        }

        [Test]
        public void TestExceptionsDigest()
        {
            var isap = new IsapDigest();

            try
            {
                isap.BlockUpdate(new byte[1], 1, 1);
                Assert.Fail(isap.AlgorithmName + ": input for BlockUpdate is too short");
            }
            catch (DataLengthException)
            {
                //expected
            }

            try
            {
                isap.DoFinal(new byte[isap.GetDigestSize() - 1], 2);
                Assert.Fail(isap.AlgorithmName + ": output for DoFinal is too short");
            }
            catch (OutputLengthException)
            {
                //expected
            }
        }

        [Test]
        public void TestParametersDigest()
        {
            var isap = new IsapDigest();

            Assert.AreEqual(32, isap.GetDigestSize(), isap.AlgorithmName + ": digest size is not correct");
        }

        [Test]
        public void TestVectorsDigest()
        {
            Random random = new Random();
            var isap = new IsapDigest();
            var map = new Dictionary<string, string>();
            using (var src = new StreamReader(SimpleTest.GetTestDataAsStream("crypto.isap.LWC_HASH_KAT_256.txt")))
            {
                string line;
                while ((line = src.ReadLine()) != null)
                {
                    int eqPos = line.IndexOf('=');
                    if (eqPos >= 0)
                    {
                        var key = line.Substring(0, eqPos).Trim();
                        var val = line.Substring(eqPos + 1).Trim();
                        map[key] = val;
                        continue;
                    }

                    byte[] ptByte = Hex.Decode(map["Msg"]);
                    byte[] expected = Hex.Decode(map["MD"]);
                    map.Clear();

                    byte[] hash = new byte[isap.GetDigestSize()];

                    isap.BlockUpdate(ptByte, 0, ptByte.Length);
                    isap.DoFinal(hash, 0);
                    Assert.True(Arrays.AreEqual(expected, hash));

                    if (ptByte.Length > 1)
                    {
                        int split = random.Next(1, ptByte.Length);
                        isap.BlockUpdate(ptByte, 0, split);
                        isap.BlockUpdate(ptByte, split, ptByte.Length - split);
                        isap.DoFinal(hash, 0);
                        Assert.IsTrue(Arrays.AreEqual(expected, hash));
                    }
                }
            }
        }
    }
}
