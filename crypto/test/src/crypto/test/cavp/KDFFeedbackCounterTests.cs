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
    public class KdfFeedbackCounterTests : SimpleTest
    {
        public override string Name
        {
            get { return "KdfFeedbackCounterTests"; }
        }

        [Test]
        public override void PerformTest()
        {
            KdfFeedbackCounterTest();
            KdfFeedbackNoCounterTest();
        }

        private void KdfFeedbackNoCounterTest()
        {
            string file = "KDFFeedbackNoCounter_gen.rsp";
            ArrayList vectors = CavpReader.ReadVectorFile(file);

            foreach (Vector vector in vectors)
            {
                IMac prf = CavpReader.CreatePrf(vector);
                KdfFeedbackBytesGenerator gen = new KdfFeedbackBytesGenerator(prf);

                int count = vector.ValueAsInt("COUNT");
                int l = vector.ValueAsInt("L");
                byte[] ki = vector.ValueAsBytes("KI");
                byte[] iv = vector.ValueAsBytes("IV");
                byte[] fixedInputData = vector.ValueAsBytes("FixedInputData");
                KdfFeedbackParameters param = KdfFeedbackParameters.CreateWithoutCounter(ki, iv, fixedInputData);
                gen.Init(param);

                byte[] koGenerated = new byte[l / 8];
                gen.GenerateBytes(koGenerated, 0, koGenerated.Length);

                byte[] koVectors = vector.ValueAsBytes("KO");
                CompareKO(file, vector, count, koGenerated, koVectors);
            }
        }

        private void KdfFeedbackCounterTest()
        {
            string file = "KDFFeedbackCounter_gen.rsp";
            ArrayList vectors = CavpReader.ReadVectorFile(file);

            foreach (Vector vector in vectors)
            {
                if (vector.HeaderAsString("CTRLOCATION") != "AFTER_ITER")
                    continue;

                IMac prf = CavpReader.CreatePrf(vector);
                KdfFeedbackBytesGenerator gen = new KdfFeedbackBytesGenerator(prf);
                int r = -1;
                {
                    string rlen = vector.HeaderAsString("RLEN");
                    if (rlen == null)
                    {
                       Fail("No RLEN");
                    }
                    r = Int32.Parse(rlen.Split('_')[0]);
                }
                int count = vector.ValueAsInt("COUNT");
                int l = vector.ValueAsInt("L");
                byte[] ki = vector.ValueAsBytes("KI");
                byte[] iv = vector.ValueAsBytes("IV");
                byte[] fixedInputData = vector.ValueAsBytes("FixedInputData");
                KdfFeedbackParameters param = KdfFeedbackParameters.CreateWithCounter(ki, iv, fixedInputData, r);
                gen.Init(param);

                byte[] koGenerated = new byte[l / 8];
                gen.GenerateBytes(koGenerated, 0, koGenerated.Length);

                byte[] koVectors = vector.ValueAsBytes("KO");
                CompareKO(file, vector, count, koGenerated, koVectors);
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