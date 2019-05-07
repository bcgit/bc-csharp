using System;
using System.Collections;
using NUnit.Core;
using NUnit.Framework;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Crypto.Tests.Cavp
{
    [TestFixture]
    public class KDFDoublePipelineTests : SimpleTest
    {
        public override string Name
        {
            get { return "KDFDoublePipelineTests"; }
        }

        [Test]
        public override void PerformTest()
        {
            KDFDblPipelineNoCounter();
            KDFDblPipelineCounter();
        }




        public void KDFDblPipelineNoCounter()
        {
            string file = "KDFDblPipelineNoCounter_gen.rsp";
            ArrayList vectors = CavpReader.readVectorFile(file);

            foreach (object _vector in vectors)
            {
                Vector vector = _vector as Vector;


                IMac prf = CavpReader.CreatePRF(vector);
                KdfDoublePipelineIterationBytesGenerator gen = new KdfDoublePipelineIterationBytesGenerator(prf);

                int count = vector.ValueAsInt("COUNT");
                int l = vector.ValueAsInt("L");
                byte[] ki = vector.ValueAsBytes("KI");
                byte[] fixedInputData = vector.ValueAsBytes("FixedInputData");
                KdfDoublePipelineIterationParameters param = KdfDoublePipelineIterationParameters.CreateWithoutCounter(ki, fixedInputData);
                gen.Init(param);

                byte[] koGenerated = new byte[l / 8];
                gen.GenerateBytes(koGenerated, 0, koGenerated.Length);

                byte[] koVectors = vector.ValueAsBytes("KO");

                compareKO(file, vector, count, koGenerated, koVectors);

            }
        }





        public void KDFDblPipelineCounter()
        {
            string file = "KDFDblPipelineCounter_gen.rsp";
            ArrayList vectors = CavpReader.readVectorFile(file);

            foreach (object _vector in vectors)
            {
                Vector vector = _vector as Vector;
                if (vector.HeaderAsString("CTRLOCATION") != "AFTER_ITER")
                {
                    continue;
                }

                IMac prf = CavpReader.CreatePRF(vector);
                KdfDoublePipelineIterationBytesGenerator gen = new KdfDoublePipelineIterationBytesGenerator(prf);
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
                byte[] fixedInputData = vector.ValueAsBytes("FixedInputData");
                KdfDoublePipelineIterationParameters param = KdfDoublePipelineIterationParameters.CreateWithCounter(ki, fixedInputData, r);
                gen.Init(param);

                byte[] koGenerated = new byte[l / 8];
                gen.GenerateBytes(koGenerated, 0, koGenerated.Length);

                byte[] koVectors = vector.ValueAsBytes("KO");

                compareKO(file, vector, count, koGenerated, koVectors);

            }
        }

        private static void compareKO(
            string name, Vector config, int test, byte[] calculatedOKM, byte[] testOKM)
        {
            if (!Arrays.AreEqual(calculatedOKM, testOKM))
            {
                throw new TestFailedException(new SimpleTestResult(
                    false, name + " using " + config.ValueAsInt("COUNT") + " test " + test + " failed"));
            }
        }
    }
}