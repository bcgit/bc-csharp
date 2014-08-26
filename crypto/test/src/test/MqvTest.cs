using System;

using NUnit.Framework;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Tests
{
	[TestFixture]
	public class MqvTest
		: SimpleTest
	{
		public override string Name
		{
			get { return "MQV"; }
		}

		public override void PerformTest()
		{
			TestECMqv();
		}

		[Test]
		public void TestECMqv()
		{
			IAsymmetricCipherKeyPairGenerator g = GeneratorUtilities.GetKeyPairGenerator("ECMQV");

//			EllipticCurve curve = new EllipticCurve(
//				new ECFieldFp(new BigInteger("883423532389192164791648750360308885314476597252960362792450860609699839")), // q
//				new BigInteger("7fffffffffffffffffffffff7fffffffffff8000000000007ffffffffffc", 16), // a
//				new BigInteger("6b016c3bdcf18941d0d654921475ca71a9db2fb27d1d37796185c2942c0a", 16)); // b
			ECCurve curve = new FpCurve(
				new BigInteger("883423532389192164791648750360308885314476597252960362792450860609699839"), // q
				new BigInteger("7fffffffffffffffffffffff7fffffffffff8000000000007ffffffffffc", 16), // a
				new BigInteger("6b016c3bdcf18941d0d654921475ca71a9db2fb27d1d37796185c2942c0a", 16)); // b

			ECDomainParameters ecSpec = new ECDomainParameters(
				curve,
//				ECPointUtil.DecodePoint(curve, Hex.Decode("020ffa963cdca8816ccc33b8642bedf905c3d358573d3f27fbbd3b3cb9aaaf")), // G
				curve.DecodePoint(Hex.Decode("020ffa963cdca8816ccc33b8642bedf905c3d358573d3f27fbbd3b3cb9aaaf")), // G
				new BigInteger("883423532389192164791648750360308884807550341691627752275345424702807307"), // n
				BigInteger.One); //1); // h

//			g.initialize(ecSpec, new SecureRandom());
			g.Init(new ECKeyGenerationParameters(ecSpec, new SecureRandom()));
			
			//
			// U side
			//
			AsymmetricCipherKeyPair U1 = g.GenerateKeyPair();
			AsymmetricCipherKeyPair U2 = g.GenerateKeyPair();
			
			IBasicAgreement uAgree = AgreementUtilities.GetBasicAgreement("ECMQV");
			uAgree.Init(new MqvPrivateParameters(
				(ECPrivateKeyParameters)U1.Private,
				(ECPrivateKeyParameters)U2.Private,
				(ECPublicKeyParameters)U2.Public));
			
			//
			// V side
			//
			AsymmetricCipherKeyPair V1 = g.GenerateKeyPair();
			AsymmetricCipherKeyPair V2 = g.GenerateKeyPair();

			IBasicAgreement vAgree = AgreementUtilities.GetBasicAgreement("ECMQV");
			vAgree.Init(new MqvPrivateParameters(
				(ECPrivateKeyParameters)V1.Private,
				(ECPrivateKeyParameters)V2.Private,
				(ECPublicKeyParameters)V2.Public));
			
			//
			// agreement
			//
			BigInteger ux = uAgree.CalculateAgreement(new MqvPublicParameters(
				(ECPublicKeyParameters)V1.Public,
				(ECPublicKeyParameters)V2.Public));
			BigInteger vx = vAgree.CalculateAgreement(new MqvPublicParameters(
				(ECPublicKeyParameters)U1.Public,
				(ECPublicKeyParameters)U2.Public));

			if (!ux.Equals(vx))
			{
				Fail("Agreement failed");
			}
		}

		public static void Main(
			string[] args)
		{
			RunTest(new MqvTest());
		}
	}
}
