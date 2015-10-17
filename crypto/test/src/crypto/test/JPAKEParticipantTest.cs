﻿using System;

using NUnit.Framework;

using Org.BouncyCastle.Crypto.Agreement.Jpake;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Crypto.Tests
{
    [TestFixture]
    public class JPAKEParticipantTest
        : SimpleTest
    {
        public override void PerformTest()
        {
            TestConstruction();
            TestSuccessfulExchange();
            TestIncorrectPassword();
            TestStateValidation();
            TestValidateRound1PayloadReceived();
            TestValidateRound2PayloadReceived();
        }

        public override string Name
        {
            get { return "JPAKEParticipant"; }
        }

        public static void Main(
            string[] args)
        {
            RunTest(new JPAKEParticipantTest());
        }

        [Test]
        public void TestFunction()
        {
            string resultText = Perform().ToString();

            Assert.AreEqual(Name + ": Okay", resultText);
        }

        public void TestConstruction()
        {
            JPAKEPrimeOrderGroup group = JPAKEPrimeOrderGroups.SUN_JCE_1024;
            SecureRandom random = new SecureRandom();
            IDigest digest = new Sha256Digest();
            string participantId = "participantId";
            char[] password = "password".ToCharArray();

            // should succeed
            new JPAKEParticipant(participantId, password, group, digest, random);

            // null participantId
            try
            {
                new JPAKEParticipant(null, password, group, digest, random);

                Fail("failed to throw exception on null participantId");
            }
            catch (NullReferenceException)
            {
                // expected
            }

            // null password
            try
            {
                new JPAKEParticipant(participantId, null, group, digest, random);

                Fail("failed to throw exception on null password");
            }
            catch (NullReferenceException)
            {
                // expected
            }

            // empty password
            try
            {
                new JPAKEParticipant(participantId, "".ToCharArray(), group, digest, random);

                Fail("failed to throw exception on empty password");
            }
            catch (ArgumentException)
            {
                // expected
            }

            // null group
            try
            {
                new JPAKEParticipant(participantId, password, null, digest, random);

                Fail("failed to throw exception on null group");
            }
            catch (NullReferenceException)
            {
                // expected
            }

            // null digest
            try
            {
                new JPAKEParticipant(participantId, password, group, null, random);

                Fail("failed to throw exception on null digest");
            }
            catch (NullReferenceException)
            {
                // expected
            }

            // null random
            try
            {
                new JPAKEParticipant(participantId, password, group, digest, null);

                Fail("failed to throw exception on null random");
            }
            catch (NullReferenceException)
            {
                // expected
            }
        }

        public void TestSuccessfulExchange()
        {
            JPAKEParticipant alice = CreateAlice();
            JPAKEParticipant bob = CreateBob();

            ExchangeAfterRound2Creation exchange = RunExchangeUntilRound2Creation(alice, bob);

            alice.ValidateRound2PayloadReceived(exchange.bobRound2Payload);
            bob.ValidateRound2PayloadReceived(exchange.aliceRound2Payload);

            BigInteger aliceKeyingMaterial = alice.CalculateKeyingMaterial();
            BigInteger bobKeyingMaterial = bob.CalculateKeyingMaterial();

            JPAKERound3Payload aliceRound3Payload = alice.CreateRound3PayloadToSend(aliceKeyingMaterial);
            JPAKERound3Payload bobRound3Payload = bob.CreateRound3PayloadToSend(bobKeyingMaterial);

            alice.ValidateRound3PayloadReceived(bobRound3Payload, aliceKeyingMaterial);
            bob.ValidateRound3PayloadReceived(aliceRound3Payload, bobKeyingMaterial);

            Assert.AreEqual(aliceKeyingMaterial, bobKeyingMaterial);
        }

        public void TestIncorrectPassword()
        {
            JPAKEParticipant alice = CreateAlice();
            JPAKEParticipant bob = CreateBobWithWrongPassword();

            ExchangeAfterRound2Creation exchange = RunExchangeUntilRound2Creation(alice, bob);

            alice.ValidateRound2PayloadReceived(exchange.bobRound2Payload);
            bob.ValidateRound2PayloadReceived(exchange.aliceRound2Payload);

            BigInteger aliceKeyingMaterial = alice.CalculateKeyingMaterial();
            BigInteger bobKeyingMaterial = bob.CalculateKeyingMaterial();

            JPAKERound3Payload aliceRound3Payload = alice.CreateRound3PayloadToSend(aliceKeyingMaterial);
            JPAKERound3Payload bobRound3Payload = bob.CreateRound3PayloadToSend(bobKeyingMaterial);

            try
            {
                alice.ValidateRound3PayloadReceived(bobRound3Payload, aliceKeyingMaterial);

                Fail("failed to throw exception on incorrect password");
            }
            catch (CryptoException)
            {
                // expected
            }

            try
            {
                bob.ValidateRound3PayloadReceived(aliceRound3Payload, bobKeyingMaterial);

                Fail("failed to throw exception on incorrect password");
            }
            catch (CryptoException)
            {
                // expected
            }
        }

        public void TestStateValidation()
        {
            JPAKEParticipant alice = CreateAlice();
            JPAKEParticipant bob = CreateBob();

            // We're testing alice here. Bob is just used for help.

            // START ROUND 1 CHECKS

            Assert.AreEqual(JPAKEParticipant.STATE_INITIALIZED, alice.State);

            // create round 2 before round 1
            try
            {
                alice.CreateRound2PayloadToSend();

                Fail("failed to throw on round 2 creation before 1");
            }
            catch (InvalidOperationException)
            {
                // expected
            }

            JPAKERound1Payload aliceRound1Payload = alice.CreateRound1PayloadToSend();
            Assert.AreEqual(JPAKEParticipant.STATE_ROUND_1_CREATED, alice.State);

            // create round 1 twice
            try
            {
                alice.CreateRound1PayloadToSend();

                Fail("failed to throw on round 1 creation twice");
            }
            catch (InvalidOperationException)
            {
                // expected
            }

            // create round 2 before validation round 1
            try
            {
                alice.CreateRound2PayloadToSend();

                Fail("failed to throw on round 2 creation before round 1 validation");
            }
            catch (InvalidOperationException)
            {
                // expected
            }

            // validate round 2 before validation round 1
            try
            {
                alice.ValidateRound2PayloadReceived(null);

                Fail("failed to throw on round 2 validation before round 1 validation");
            }
            catch (InvalidOperationException)
            {
                // expected
            }

            JPAKERound1Payload bobRound1Payload = bob.CreateRound1PayloadToSend();
            alice.ValidateRound1PayloadReceived(bobRound1Payload);
            Assert.AreEqual(JPAKEParticipant.STATE_ROUND_1_VALIDATED, alice.State);

            // validate round 1 payload twice
            try
            {
                alice.ValidateRound1PayloadReceived(bobRound1Payload);

                Fail("failed to throw on round 1 validation twice");
            }
            catch (InvalidOperationException)
            {
                // expected
            }

            bob.ValidateRound1PayloadReceived(aliceRound1Payload);

            // START ROUND 2 CHECKS

            JPAKERound2Payload aliceRound2Payload = alice.CreateRound2PayloadToSend();
            Assert.AreEqual(JPAKEParticipant.STATE_ROUND_2_CREATED, alice.State);

            // create round 2 payload twice
            try
            {
                alice.CreateRound2PayloadToSend();

                Fail("failed to throw on round 2 creation twice");
            }
            catch (InvalidOperationException)
            {
                // expected
            }

            // create key before validation round 2
            try
            {
                alice.CalculateKeyingMaterial();

                Fail("failed to throw on calculating keying material before round 2 validation");
            }
            catch (InvalidOperationException)
            {
                // expected
            }

            // validate round 3 before validating round 2
            try
            {
                alice.ValidateRound3PayloadReceived(null, null);

                Fail("failed to throw on validating round 3 before 2");
            }
            catch (InvalidOperationException)
            {
                // expected
            }

            JPAKERound2Payload bobRound2Payload = bob.CreateRound2PayloadToSend();
            alice.ValidateRound2PayloadReceived(bobRound2Payload);
            Assert.AreEqual(JPAKEParticipant.STATE_ROUND_2_VALIDATED, alice.State);

            // validate round 2 payload twice
            try
            {
                alice.ValidateRound2PayloadReceived(bobRound2Payload);

                Fail("failed to throw on validating round 2 twice");
            }
            catch (InvalidOperationException)
            {
                // expected
            }

            bob.ValidateRound2PayloadReceived(aliceRound2Payload);

            // create round 3 before calculating key
            try
            {
                alice.CreateRound3PayloadToSend(BigInteger.One);

                Fail("failed to throw on creating round 3 before calculating key aterial");
            }
            catch (InvalidOperationException)
            {
                // expected
            }

            // START KEY CALCULATION CHECKS

            BigInteger aliceKeyingMaterial = alice.CalculateKeyingMaterial();
            Assert.AreEqual(JPAKEParticipant.STATE_KEY_CALCULATED, alice.State);

            // calculate key twice
            try
            {
                alice.CalculateKeyingMaterial();

                Fail("failed to throw on calculating key twice");
            }
            catch (InvalidOperationException)
            {
                // expected
            }

            BigInteger bobKeyingMaterial = bob.CalculateKeyingMaterial();

            // START ROUND 3 CHECKS

            JPAKERound3Payload aliceRound3Payload = alice.CreateRound3PayloadToSend(aliceKeyingMaterial);
            Assert.AreEqual(JPAKEParticipant.STATE_ROUND_3_CREATED, alice.State);

            // create round 3 payload twice
            try
            {
                alice.CreateRound3PayloadToSend(aliceKeyingMaterial);

                Fail("failed to throw on creation round 3 twice");
            }
            catch (InvalidOperationException)
            {
                // expected
            }

            JPAKERound3Payload bobRound3Payload = bob.CreateRound3PayloadToSend(bobKeyingMaterial);
            alice.ValidateRound3PayloadReceived(bobRound3Payload, aliceKeyingMaterial);
            Assert.AreEqual(JPAKEParticipant.STATE_ROUND_3_VALIDATED, alice.State);

            // validate round 3 payload twice
            try
            {
                alice.ValidateRound3PayloadReceived(bobRound3Payload, aliceKeyingMaterial);

                Fail("failed to throw on validation round 3 twice");
            }
            catch (InvalidOperationException)
            {
                // expected
            }

            bob.ValidateRound3PayloadReceived(aliceRound3Payload, bobKeyingMaterial);
        }

        public void TestValidateRound1PayloadReceived()
        {
            // We're testing alice here. Bob is just used for help.

            JPAKERound1Payload bobRound1Payload = CreateBob().CreateRound1PayloadToSend();

            // should succeed
            CreateAlice().ValidateRound1PayloadReceived(bobRound1Payload);

            // alice verifies alice's payload
            try
            {
                JPAKEParticipant alice = CreateAlice();
                alice.ValidateRound1PayloadReceived(alice.CreateRound1PayloadToSend());

                Fail("failed to throw on participant validating own payload");
            }
            catch (CryptoException)
            {
                // expected
            }

            // g^x4 == 1
            try
            {
                CreateAlice().ValidateRound1PayloadReceived(new JPAKERound1Payload(
                    bobRound1Payload.ParticipantId,
                    bobRound1Payload.Gx1,
                    BigInteger.One,
                    bobRound1Payload.KnowledgeProofForX1,
                    bobRound1Payload.KnowledgeProofForX2));

                Fail("failed to throw on g^x4 == 1");
            }
            catch (CryptoException)
            {
                // expected
            }

            // zero knowledge proof for x3 fails
            try
            {
                JPAKERound1Payload bobRound1Payload2 = CreateBob().CreateRound1PayloadToSend();
                CreateAlice().ValidateRound1PayloadReceived(new JPAKERound1Payload(
                    bobRound1Payload.ParticipantId,
                    bobRound1Payload.Gx1,
                    bobRound1Payload.Gx2,
                    bobRound1Payload2.KnowledgeProofForX1,
                    bobRound1Payload.KnowledgeProofForX2));

                Fail("failed to throw on incorrect zero knowledge proof for x3");
            }
            catch (CryptoException)
            {
                // expected
            }

            // zero knowledge proof for x4 fails
            try
            {
                JPAKERound1Payload bobRound1Payload2 = CreateBob().CreateRound1PayloadToSend();
                CreateAlice().ValidateRound1PayloadReceived(new JPAKERound1Payload(
                    bobRound1Payload.ParticipantId,
                    bobRound1Payload.Gx1,
                    bobRound1Payload.Gx2,
                    bobRound1Payload.KnowledgeProofForX1,
                    bobRound1Payload2.KnowledgeProofForX2));

                Fail("failed to throw on incorrect zero knowledge proof for x4");
            }
            catch (CryptoException)
            {
                // expected
            }
        }

        public void TestValidateRound2PayloadReceived()
        {
            // We're testing alice here. Bob is just used for help.

            // should succeed
            ExchangeAfterRound2Creation exchange1 = RunExchangeUntilRound2Creation(CreateAlice(), CreateBob());
            exchange1.alice.ValidateRound2PayloadReceived(exchange1.bobRound2Payload);

            // alice verified alice's payload
            ExchangeAfterRound2Creation exchange2 = RunExchangeUntilRound2Creation(CreateAlice(), CreateBob());
            try
            {
                exchange2.alice.ValidateRound2PayloadReceived(exchange2.aliceRound2Payload);

                Fail("failed to throw on participant verifying own payload 2");
            }
            catch (CryptoException)
            {
                // expected
            }

            // wrong z
            ExchangeAfterRound2Creation exchange3 = RunExchangeUntilRound2Creation(CreateAlice(), CreateBob());
            ExchangeAfterRound2Creation exchange4 = RunExchangeUntilRound2Creation(CreateAlice(), CreateBob());
            try
            {
                exchange3.alice.ValidateRound2PayloadReceived(exchange4.bobRound2Payload);

                Fail("failed to throw on wrong z");
            }
            catch (CryptoException)
            {
                // expected
            }
        }

        private class ExchangeAfterRound2Creation
        {
            public JPAKEParticipant alice;
            public JPAKERound2Payload aliceRound2Payload;
            public JPAKERound2Payload bobRound2Payload;

            public ExchangeAfterRound2Creation(
                JPAKEParticipant alice,
                JPAKERound2Payload aliceRound2Payload,
                JPAKERound2Payload bobRound2Payload)
            {
                this.alice = alice;
                this.aliceRound2Payload = aliceRound2Payload;
                this.bobRound2Payload = bobRound2Payload;
            }
        }

        private ExchangeAfterRound2Creation RunExchangeUntilRound2Creation(JPAKEParticipant alice, JPAKEParticipant bob)
        {
            JPAKERound1Payload aliceRound1Payload = alice.CreateRound1PayloadToSend();
            JPAKERound1Payload bobRound1Payload = bob.CreateRound1PayloadToSend();

            alice.ValidateRound1PayloadReceived(bobRound1Payload);
            bob.ValidateRound1PayloadReceived(aliceRound1Payload);

            JPAKERound2Payload aliceRound2Payload = alice.CreateRound2PayloadToSend();
            JPAKERound2Payload bobRound2Payload = bob.CreateRound2PayloadToSend();

            return new ExchangeAfterRound2Creation(
                alice,
                aliceRound2Payload,
                bobRound2Payload);
        }

        private JPAKEParticipant CreateAlice()
        {
            return CreateParticipant("alice", "password");
        }

        private JPAKEParticipant CreateBob()
        {
            return CreateParticipant("bob", "password");
        }

        private JPAKEParticipant CreateBobWithWrongPassword()
        {
            return CreateParticipant("bob", "wrong");
        }

        private JPAKEParticipant CreateParticipant(string participantId, string password)
        {
            return new JPAKEParticipant(
                participantId,
                password.ToCharArray(),
                JPAKEPrimeOrderGroups.SUN_JCE_1024);
        }
    }
}
