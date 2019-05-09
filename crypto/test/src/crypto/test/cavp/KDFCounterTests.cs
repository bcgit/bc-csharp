using System;
using System.Collections;

using NUnit.Framework;

using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Crypto.Tests.Cavp
{
    [TestFixture]
    public class KdfCounterTests : SimpleTest
    {
        public KdfCounterTests()
        {
        }

        public override string Name
        {
            get { return "KdfCounterTests"; }
        }

        [Test]
        public override void PerformTest()
        {
            string file = "KDFCTR_gen.rsp";
            ArrayList vectors = CavpReader.ReadVectorFile(file);
            ProcessVectors(file, vectors);
        }

        private void ProcessVectors(string name, ArrayList vectors)
        {
            foreach (Vector vector in vectors)
            {
                IMac prf = CavpReader.CreatePrf(vector);
                KdfCounterBytesGenerator gen = new KdfCounterBytesGenerator(prf);
                int r = -1;
                {
                    string rlen = vector.HeaderAsString("RLEN");
                    if (rlen == null)
                    {
                        Assert.Fail("No RLEN");
                    }
                    r = Int32.Parse(rlen.Split('_')[0]);
                }
                int count = vector.ValueAsInt("COUNT");
                int l = vector.ValueAsInt("L");
                byte[] ki = vector.ValueAsBytes("KI");
                if (vector.HeaderAsString("CTRLOCATION") == "BEFORE_FIXED")
                {
                    byte[] fixedInputData = vector.ValueAsBytes("FixedInputData");
                    KdfCounterParameters param = new KdfCounterParameters(ki, null, fixedInputData, r);
                    gen.Init(param);
                }
                else if (vector.HeaderAsString("CTRLOCATION") == "AFTER_FIXED")
                {
                    byte[] fixedInputData = vector.ValueAsBytes("FixedInputData");
                    KdfCounterParameters param = new KdfCounterParameters(ki, fixedInputData, null, r);
                    gen.Init(param);
                }
                else if (vector.HeaderAsString("CTRLOCATION") == "MIDDLE_FIXED")
                {
                    byte[] DataBeforeCtrData = vector.ValueAsBytes("DataBeforeCtrData");
                    byte[] DataAfterCtrData = vector.ValueAsBytes("DataAfterCtrData");
                    KdfCounterParameters param = new KdfCounterParameters(ki, DataBeforeCtrData, DataAfterCtrData, r);
                    gen.Init(param);
                }
                else
                {
                    throw new InvalidOperationException("Unknown CTRLOCATION: " + vector.HeaderAsString("CTRLOCATION"));
                }

                byte[] koGenerated = new byte[l / 8];
                gen.GenerateBytes(koGenerated, 0, koGenerated.Length);

                byte[] koVectors = vector.ValueAsBytes("KO");
                CompareKO(name, vector, count, koGenerated, koVectors);
            }
        }

        private static void CompareKO(string name, Vector config, int test, byte[] calculatedOKM, byte[] testOKM)
        {
            if (!Arrays.AreEqual(calculatedOKM, testOKM))
            {
                throw new TestFailedException(new SimpleTestResult(
                    false, name + " using " + config.ValueAsInt("COUNT") + " test " + test + " failed"));
            }
        }
    }
}