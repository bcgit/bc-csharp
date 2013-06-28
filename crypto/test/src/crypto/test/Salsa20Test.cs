using System;

using NUnit.Framework;

using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Crypto.Tests
{
	/**
	* Salsa20 Test
	*/
	[TestFixture]
	public class Salsa20Test
		: SimpleTest
	{
		private static readonly byte[] zeroes = Hex.Decode(
			  "00000000000000000000000000000000"
			+ "00000000000000000000000000000000"
			+ "00000000000000000000000000000000"
			+ "00000000000000000000000000000000");

		private static readonly string set1v0_0 =
			  "4DFA5E481DA23EA09A31022050859936"
			+ "DA52FCEE218005164F267CB65F5CFD7F"
			+ "2B4F97E0FF16924A52DF269515110A07"
			+ "F9E460BC65EF95DA58F740B7D1DBB0AA";

		private static readonly string set1v0_192 =
			  "DA9C1581F429E0A00F7D67E23B730676"
			+ "783B262E8EB43A25F55FB90B3E753AEF"
			+ "8C6713EC66C51881111593CCB3E8CB8F"
			+ "8DE124080501EEEB389C4BCB6977CF95";

		private static readonly string set1v0_256 =
			  "7D5789631EB4554400E1E025935DFA7B"
			+ "3E9039D61BDC58A8697D36815BF1985C"
			+ "EFDF7AE112E5BB81E37ECF0616CE7147"
			+ "FC08A93A367E08631F23C03B00A8DA2F";

		private static readonly string set1v0_448 =
			  "B375703739DACED4DD4059FD71C3C47F"
			+ "C2F9939670FAD4A46066ADCC6A564578"
			+ "3308B90FFB72BE04A6B147CBE38CC0C3"
			+ "B9267C296A92A7C69873F9F263BE9703";

		private static readonly string set1v9_0 =
			  "0471076057830FB99202291177FBFE5D"
			+ "38C888944DF8917CAB82788B91B53D1C"
			+ "FB06D07A304B18BB763F888A61BB6B75"
			+ "5CD58BEC9C4CFB7569CB91862E79C459";

		private static readonly string set1v9_192 =
			  "D1D7E97556426E6CFC21312AE3811425"
			+ "9E5A6FB10DACBD88E4354B0472556935"
			+ "2B6DA5ACAFACD5E266F9575C2ED8E6F2"
			+ "EFE4B4D36114C3A623DD49F4794F865B";

		private static readonly string set1v9_256 =
			  "AF06FAA82C73291231E1BD916A773DE1"
			+ "52FD2126C40A10C3A6EB40F22834B8CC"
			+ "68BD5C6DBD7FC1EC8F34165C517C0B63"
			+ "9DB0C60506D3606906B8463AA0D0EC2F";

		private static readonly string set1v9_448 =
			  "AB3216F1216379EFD5EC589510B8FD35"
			+ "014D0AA0B613040BAE63ECAB90A9AF79"
			+ "661F8DA2F853A5204B0F8E72E9D9EB4D"
			+ "BA5A4690E73A4D25F61EE7295215140C";

		private static readonly string set6v0_0 =
			  "F5FAD53F79F9DF58C4AEA0D0ED9A9601"
			+ "F278112CA7180D565B420A48019670EA"
			+ "F24CE493A86263F677B46ACE1924773D"
			+ "2BB25571E1AA8593758FC382B1280B71";

		private static readonly string set6v0_65472 =
			  "B70C50139C63332EF6E77AC54338A407"
			+ "9B82BEC9F9A403DFEA821B83F7860791"
			+ "650EF1B2489D0590B1DE772EEDA4E3BC"
			+ "D60FA7CE9CD623D9D2FD5758B8653E70";

		private static readonly string set6v0_65536 =
			  "81582C65D7562B80AEC2F1A673A9D01C"
			+ "9F892A23D4919F6AB47B9154E08E699B"
			+ "4117D7C666477B60F8391481682F5D95"
			+ "D96623DBC489D88DAA6956B9F0646B6E";

		private static readonly string set6v1_0 =
			  "3944F6DC9F85B128083879FDF190F7DE"
			+ "E4053A07BC09896D51D0690BD4DA4AC1"
			+ "062F1E47D3D0716F80A9B4D85E6D6085"
			+ "EE06947601C85F1A27A2F76E45A6AA87";

		private static readonly string set6v1_65472 =
			  "36E03B4B54B0B2E04D069E690082C8C5"
			+ "92DF56E633F5D8C7682A02A65ECD1371"
			+ "8CA4352AACCB0DA20ED6BBBA62E177F2"
			+ "10E3560E63BB822C4158CAA806A88C82";

		private static readonly string set6v1_65536 =
			  "1B779E7A917C8C26039FFB23CF0EF8E0"
			+ "8A1A13B43ACDD9402CF5DF38501098DF"
			+ "C945A6CC69A6A17367BC03431A86B3ED"
			+ "04B0245B56379BF997E25800AD837D7D";

		public override string Name
		{
			get { return "Salsa20"; }
		}

		public override void PerformTest()
		{
			salsa20Test1(new ParametersWithIV(new KeyParameter(Hex.Decode("80000000000000000000000000000000")), Hex.Decode("0000000000000000")),
					set1v0_0, set1v0_192,  set1v0_256,  set1v0_448);
			salsa20Test1(new ParametersWithIV(new KeyParameter(Hex.Decode("00400000000000000000000000000000")), Hex.Decode("0000000000000000")),
					set1v9_0, set1v9_192,  set1v9_256,  set1v9_448);
			salsa20Test2(new ParametersWithIV(new KeyParameter(Hex.Decode("0053A6F94C9FF24598EB3E91E4378ADD3083D6297CCF2275C81B6EC11467BA0D")), Hex.Decode("0D74DB42A91077DE")),
					set6v0_0, set6v0_65472, set6v0_65536);
			salsa20Test2(new ParametersWithIV(new KeyParameter(Hex.Decode("0558ABFE51A4F74A9DF04396E93C8FE23588DB2E81D4277ACD2073C6196CBF12")), Hex.Decode("167DE44BB21980E7")),
					set6v1_0, set6v1_65472, set6v1_65536);
			reinitBug();
		}

		private void salsa20Test1(
			ICipherParameters	parameters,
			string				v0,
			string				v192,
			string				v256,
			string				v448)
		{
			IStreamCipher salsa = new Salsa20Engine();
			byte[]       buf = new byte[64];

			salsa.Init(true, parameters);

			for (int i = 0; i != 7; i++)
			{
				salsa.ProcessBytes(zeroes, 0, 64, buf, 0);
				switch (i)
				{
				case 0:
					if (!AreEqual(buf, Hex.Decode(v0)))
					{
						mismatch("v0", v0, buf);
					}
					break;
				case 3:
					if (!AreEqual(buf, Hex.Decode(v192)))
					{
						mismatch("v192", v192, buf);
					}
					break;
				case 4:
					if (!AreEqual(buf, Hex.Decode(v256)))
					{
						mismatch("v256", v256, buf);
					}
					break;
				default:
					// ignore
					break;
				}
			}

			for (int i = 0; i != 64; i++)
			{
				buf[i] = salsa.ReturnByte(zeroes[i]);
			}

			if (!AreEqual(buf, Hex.Decode(v448)))
			{
				mismatch("v448", v448, buf);
			}       
		}

		private void salsa20Test2(
			ICipherParameters	parameters,
			string				v0,
			string				v65472,
			string				v65536)
		{
			IStreamCipher salsa = new Salsa20Engine();
			byte[]       buf = new byte[64];

			salsa.Init(true, parameters);

			for (int i = 0; i != 1025; i++)
			{
				salsa.ProcessBytes(zeroes, 0, 64, buf, 0);
				switch (i)
				{
				case 0:
					if (!AreEqual(buf, Hex.Decode(v0)))
					{
						mismatch("v0", v0, buf);
					}
					break;
				case 1023:
					if (!AreEqual(buf, Hex.Decode(v65472)))
					{
						mismatch("v65472", v65472, buf);
					}
					break;
				case 1024:
					if (!AreEqual(buf, Hex.Decode(v65536)))
					{
						mismatch("v65536", v65536, buf);
					}
					break;
				default:
					// ignore
					break;
				}
			}
		}

		private void mismatch(
			string	name,
			string	expected,
			byte[]	found)
		{
			Fail("mismatch on " + name, expected, Hex.ToHexString(found));
		}

		private void reinitBug()
		{
			KeyParameter key = new KeyParameter(Hex.Decode("80000000000000000000000000000000"));
			ParametersWithIV parameters = new ParametersWithIV(key, Hex.Decode("0000000000000000"));

			IStreamCipher salsa = new Salsa20Engine();

			salsa.Init(true, parameters);

			try
			{
				salsa.Init(true, key);
				Fail("Salsa20 should throw exception if no IV in Init");
			}
			catch (ArgumentException)
			{
			}
		}

		public static void Main(
			string[] args)
		{
			RunTest(new Salsa20Test());
		}

		[Test]
		public void TestFunction()
		{
			string resultText = Perform().ToString();

			Assert.AreEqual(Name + ": Okay", resultText);
		}
	}
}
