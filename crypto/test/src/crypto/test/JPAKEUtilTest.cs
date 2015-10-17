using System;

using NUnit.Framework;

using Org.BouncyCastle.Crypto.Agreement.Jpake;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Crypto.Tests
{
    [TestFixture]
    public class JPAKEUtilTest
        : SimpleTest
    {
        private static readonly BigInteger Ten = BigInteger.ValueOf(10);

        public override void PerformTest()
        {
            TestValidateGx4();
            TestValidateGa();
            TestValidateParticipantIdsDiffer();
            TestValidateParticipantsIdsEqual();
            TestValidateMacTag();
            TestValidateNotNull();
            TestValidateZeroKnowledgeProof();
        }

        public override string Name
        {
            get { return "JPAKEUtil"; }
        }

        public static void Main(
            string[] args)
        {
            RunTest(new JPAKEUtilTest());
        }

        [Test]
        public void TestFunction()
        {
            string resultText = Perform().ToString();

            Assert.AreEqual(Name + ": Okay", resultText);
        }

        public void TestValidateGx4()
        {
            JPAKEUtil.ValidateGx4(Ten);

            try
            {
                JPAKEUtil.ValidateGx4(BigInteger.One);

                Fail("exception not thrown for g^x4 equal to 1");
            }
            catch (CryptoException)
            {
                // expected
            }
        }

        public void TestValidateGa()
        {
            JPAKEUtil.ValidateGa(Ten);

            try
            {
                JPAKEUtil.ValidateGa(BigInteger.One);

                Fail("exception not thrown for g^a equal to 1");
            }
            catch (CryptoException)
            {
                // expected
            }
        }

        public void TestValidateParticipantIdsDiffer()
        {
            JPAKEUtil.ValidateParticipantIdsDiffer("a", "b");
            JPAKEUtil.ValidateParticipantIdsDiffer("a", "A");

            try
            {
                JPAKEUtil.ValidateParticipantIdsDiffer("a", "a");

                Fail("validate participant ids differ not throwing exception for equal participant ids");
            }
            catch (CryptoException)
            {
                // expected
            }
        }

        public void TestValidateParticipantsIdsEqual()
        {
            JPAKEUtil.ValidateParticipantIdsEqual("a", "a");

            try
            {
                JPAKEUtil.ValidateParticipantIdsEqual("a", "b");

                Fail("validate participant ids equal not throwing exception for different participant ids");
            }
            catch (CryptoException)
            {
                // expected
            }
        }

        public void TestValidateMacTag()
        {
            JPAKEPrimeOrderGroup pg1 = JPAKEPrimeOrderGroups.SUN_JCE_1024;

            SecureRandom random = new SecureRandom();
            IDigest digest = new Sha256Digest();

            BigInteger x1 = JPAKEUtil.GenerateX1(pg1.Q, random);
            BigInteger x2 = JPAKEUtil.GenerateX2(pg1.Q, random);
            BigInteger x3 = JPAKEUtil.GenerateX1(pg1.Q, random);
            BigInteger x4 = JPAKEUtil.GenerateX2(pg1.Q, random);

            BigInteger gx1 = JPAKEUtil.CalculateGx(pg1.P, pg1.G, x1);
            BigInteger gx2 = JPAKEUtil.CalculateGx(pg1.P, pg1.G, x2);
            BigInteger gx3 = JPAKEUtil.CalculateGx(pg1.P, pg1.G, x3);
            BigInteger gx4 = JPAKEUtil.CalculateGx(pg1.P, pg1.G, x4);

            BigInteger gB = JPAKEUtil.CalculateGA(pg1.P, gx3, gx1, gx2);

            BigInteger s = JPAKEUtil.CalculateS("password".ToCharArray());

            BigInteger xs = JPAKEUtil.CalculateX2s(pg1.Q, x4, s);

            BigInteger B = JPAKEUtil.CalculateA(pg1.P, pg1.Q, gB, xs);

            BigInteger keyingMaterial = JPAKEUtil.CalculateKeyingMaterial(pg1.P, pg1.Q, gx4, x2, s, B);

            BigInteger macTag = JPAKEUtil.CalculateMacTag("participantId", "partnerParticipantId", gx1, gx2, gx3, gx4, keyingMaterial, digest);

            // should succeed
            JPAKEUtil.ValidateMacTag("partnerParticipantId", "participantId", gx3, gx4, gx1, gx2, keyingMaterial, digest, macTag);

            // validating own macTag (as opposed to the other party's mactag)
            try
            {
                JPAKEUtil.ValidateMacTag("participantId", "partnerParticipantId", gx1, gx2, gx3, gx4, keyingMaterial, digest, macTag);

                Fail("failed to throw exception on validating own macTag (calculated partner macTag)");
            }
            catch (CryptoException)
            {
                // expected
            }

            // participant ids switched
            try
            {
                JPAKEUtil.ValidateMacTag("participantId", "partnerParticipantId", gx3, gx4, gx1, gx2, keyingMaterial, digest, macTag);

                Fail("failed to throw exception on validating own macTag (calculated partner macTag");
            }
            catch (CryptoException)
            {
                // expected
            }
        }

        public void TestValidateNotNull()
        {
            JPAKEUtil.ValidateNotNull("a", "description");

            try
            {
                JPAKEUtil.ValidateNotNull(null, "description");

                Fail("failed to throw exception on null");
            }
            catch (NullReferenceException)
            {
                // expected
            }
        }

        public void TestValidateZeroKnowledgeProof()
        {
            JPAKEPrimeOrderGroup pg1 = JPAKEPrimeOrderGroups.SUN_JCE_1024;

            SecureRandom random = new SecureRandom();
            IDigest digest1 = new Sha256Digest();

            BigInteger x1 = JPAKEUtil.GenerateX1(pg1.Q, random);
            BigInteger gx1 = JPAKEUtil.CalculateGx(pg1.P, pg1.G, x1);
            string participantId1 = "participant1";

            BigInteger[] zkp1 = JPAKEUtil.CalculateZeroKnowledgeProof(pg1.P, pg1.Q, pg1.G, gx1, x1, participantId1, digest1, random);

            // should succeed
            JPAKEUtil.ValidateZeroKnowledgeProof(pg1.P, pg1.Q, pg1.G, gx1, zkp1, participantId1, digest1);

            // wrong group
            JPAKEPrimeOrderGroup pg2 = JPAKEPrimeOrderGroups.NIST_3072;
            try
            {
                JPAKEUtil.ValidateZeroKnowledgeProof(pg2.P, pg2.Q, pg2.G, gx1, zkp1, participantId1, digest1);

                Fail("failed to throw exception on wrong prime order group");
            }
            catch (CryptoException)
            {
                // expected
            }

            // wrong digest
            IDigest digest2 = new Sha1Digest();
            try
            {
                JPAKEUtil.ValidateZeroKnowledgeProof(pg1.P, pg1.Q, pg1.G, gx1, zkp1, participantId1, digest2);

                Fail("failed to throw exception on wrong digest");
            }
            catch (CryptoException)
            {
                // expected
            }

            // wrong participant
            string participantId2 = "participant2";
            try
            {
                JPAKEUtil.ValidateZeroKnowledgeProof(pg1.P, pg1.Q, pg1.G, gx1, zkp1, participantId2, digest1);

                Fail("failed to throw exception on wrong participant");
            }
            catch (CryptoException)
            {
                // expected
            }

            // wrong gx
            BigInteger x2 = JPAKEUtil.GenerateX2(pg1.Q, random);
            BigInteger gx2 = JPAKEUtil.CalculateGx(pg1.P, pg1.G, x2);
            try
            {
                JPAKEUtil.ValidateZeroKnowledgeProof(pg1.P, pg1.Q, pg1.G, gx2, zkp1, participantId1, digest1);

                Fail("failed to throw exception on wrong gx");
            }
            catch (CryptoException)
            {
                // expected
            }

            // wrong zkp
            BigInteger[] zkp2 = JPAKEUtil.CalculateZeroKnowledgeProof(pg1.P, pg1.Q, pg1.G, gx2, x2, participantId1, digest1, random);
            try
            {
                JPAKEUtil.ValidateZeroKnowledgeProof(pg1.P, pg1.Q, pg1.G, gx1, zkp2, participantId1, digest1);

                Fail("failed to throw exception on wrong zero knowledge proof");
            }
            catch (CryptoException)
            {
                // expected
            }

            // gx <= 0
            try
            {
                JPAKEUtil.ValidateZeroKnowledgeProof(pg1.P, pg1.Q, pg1.G, BigInteger.Zero, zkp1, participantId1, digest1);

                Fail("failed to throw exception on g^x <= 0");
            }
            catch (CryptoException)
            {
                // expected
            }

            // gx >= p
            try
            {
                JPAKEUtil.ValidateZeroKnowledgeProof(pg1.P, pg1.Q, pg1.G, pg1.P, zkp1, participantId1, digest1);

                Fail("failed to throw exception on g^x >= p");
            }
            catch (CryptoException)
            {
                // expected
            }

            // gx mod q == 1
            try
            {
                JPAKEUtil.ValidateZeroKnowledgeProof(pg1.P, pg1.Q, pg1.G, pg1.Q.Add(BigInteger.One), zkp1, participantId1, digest1);

                Fail("failed to throw exception on g^x mod q == 1");
            }
            catch (CryptoException)
            {
                // expected
            }
        }
    }
}
