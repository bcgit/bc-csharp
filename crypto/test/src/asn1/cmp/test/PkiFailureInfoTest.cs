using System;
using System.IO;

using NUnit.Framework;

using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Asn1.Cmp.Tests
{
    /**
     * PKIFailureInfoTest
     */
    [TestFixture]
    public class PkiFailureInfoTest
        : SimpleTest
    {
        // A correct hex encoded BAD_DATA_FORMAT PKIFailureInfo 
        private static readonly byte[] CorrectFailureInfo = Base64.Decode("AwIANQ==");

        public override string Name => "PkiFailureInfo";

        private void ImplTestEncoding()
        {
            DerBitString bitString = (DerBitString)new Asn1InputStream(CorrectFailureInfo).ReadObject();
            PkiFailureInfo correct = new PkiFailureInfo(bitString);

            PkiFailureInfo bug = new PkiFailureInfo(
                PkiFailureInfo.BadRequest | PkiFailureInfo.BadTime | PkiFailureInfo.BadDataFormat | PkiFailureInfo.IncorrectData);

            if (!AreEqual(correct.GetDerEncoded(), bug.GetDerEncoded()))
            {
                Fail("encoding doesn't match");
            }
        }

        public override void PerformTest()
        {
            TestBitStringConstant(0, PkiFailureInfo.BadAlg);
            TestBitStringConstant(1, PkiFailureInfo.BadMessageCheck);
            TestBitStringConstant(2, PkiFailureInfo.BadRequest);
            TestBitStringConstant(3, PkiFailureInfo.BadTime);
            TestBitStringConstant(4, PkiFailureInfo.BadCertId);
            TestBitStringConstant(5, PkiFailureInfo.BadDataFormat);
            TestBitStringConstant(6, PkiFailureInfo.WrongAuthority);
            TestBitStringConstant(7, PkiFailureInfo.IncorrectData);
            TestBitStringConstant(8, PkiFailureInfo.MissingTimeStamp);
            TestBitStringConstant(9, PkiFailureInfo.BadPop);
            TestBitStringConstant(10, PkiFailureInfo.CertRevoked);
            TestBitStringConstant(11, PkiFailureInfo.CertConfirmed);
            TestBitStringConstant(12, PkiFailureInfo.WrongIntegrity);
            TestBitStringConstant(13, PkiFailureInfo.BadRecipientNonce);
            TestBitStringConstant(14, PkiFailureInfo.TimeNotAvailable);
            TestBitStringConstant(15, PkiFailureInfo.UnacceptedPolicy);
            TestBitStringConstant(16, PkiFailureInfo.UnacceptedExtension);
            TestBitStringConstant(17, PkiFailureInfo.AddInfoNotAvailable);
            TestBitStringConstant(18, PkiFailureInfo.BadSenderNonce);
            TestBitStringConstant(19, PkiFailureInfo.BadCertTemplate);
            TestBitStringConstant(20, PkiFailureInfo.SignerNotTrusted);
            TestBitStringConstant(21, PkiFailureInfo.TransactionIdInUse);
            TestBitStringConstant(22, PkiFailureInfo.UnsupportedVersion);
            TestBitStringConstant(23, PkiFailureInfo.NotAuthorized);
            TestBitStringConstant(24, PkiFailureInfo.SystemUnavail);
            TestBitStringConstant(25, PkiFailureInfo.SystemFailure);
            TestBitStringConstant(26, PkiFailureInfo.DuplicateCertReq);

            ImplTestEncoding();
        }

        [Test]
        public void TestFunction()
        {
            string resultText = Perform().ToString();

            Assert.AreEqual(Name + ": Okay", resultText);
        }
    }
}
