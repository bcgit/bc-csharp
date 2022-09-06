using System.IO;
using System.Text;

using NUnit.Framework;

using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

namespace Org.BouncyCastle.Crypto.IO.Tests
{
	[TestFixture]
	public class CipherStreamTest
	{
		private const string DATA = "This will be encrypted and then decrypted and checked for correctness";

		[Test]
		public void TestEncryptDecryptA()
		{
			byte[] dataBytes = Encoding.ASCII.GetBytes(DATA);
			byte[] encryptedDataBytes = EncryptOnWrite(dataBytes);

			byte[] decryptedDataBytes = DecryptOnRead(encryptedDataBytes);
			string decryptedData = Encoding.ASCII.GetString(decryptedDataBytes, 0, decryptedDataBytes.Length);
			Assert.AreEqual(DATA, decryptedData);
		}

		[Test]
		public void TestEncryptDecryptB()
		{
			byte[] dataBytes = Encoding.ASCII.GetBytes(DATA);
			byte[] encryptedDataBytes = EncryptOnRead(dataBytes);

			byte[] decryptedDataBytes = DecryptOnWrite(encryptedDataBytes);
			string decryptedData = Encoding.ASCII.GetString(decryptedDataBytes, 0, decryptedDataBytes.Length);
			Assert.AreEqual(DATA, decryptedData);
		}

		[Test]
		public void TestEncryptDecryptC()
		{
			byte[] dataBytes = Encoding.ASCII.GetBytes(DATA);
			byte[] encryptedDataBytes = EncryptOnWrite(dataBytes);

			byte[] decryptedDataBytes = DecryptOnWrite(encryptedDataBytes);
			string decryptedData = Encoding.ASCII.GetString(decryptedDataBytes, 0, decryptedDataBytes.Length);
			Assert.AreEqual(DATA, decryptedData);
		}

		[Test]
		public void TestEncryptDecryptD()
		{
			byte[] dataBytes = Encoding.ASCII.GetBytes(DATA);
			byte[] encryptedDataBytes = EncryptOnRead(dataBytes);

			byte[] decryptedDataBytes = DecryptOnRead(encryptedDataBytes);
			string decryptedData = Encoding.ASCII.GetString(decryptedDataBytes, 0, decryptedDataBytes.Length);
			Assert.AreEqual(DATA, decryptedData);
		}

		private byte[] EncryptOnWrite(byte[] dataBytes)
		{
			MemoryStream encryptedDataStream = new MemoryStream();
			IBufferedCipher outCipher = CreateCipher(true);
			CipherStream outCipherStream = new CipherStream(encryptedDataStream, null, outCipher);
			outCipherStream.Write(dataBytes, 0, dataBytes.Length);
			Assert.AreEqual(0L, encryptedDataStream.Position % outCipher.GetBlockSize());

			outCipherStream.Close();
			byte[] encryptedDataBytes = encryptedDataStream.ToArray();
			Assert.AreEqual(dataBytes.Length, encryptedDataBytes.Length);

			return encryptedDataBytes;
		}

		private byte[] EncryptOnRead(byte[] dataBytes)
		{
			MemoryStream dataStream = new MemoryStream(dataBytes, false);
			MemoryStream encryptedDataStream = new MemoryStream();
			IBufferedCipher inCipher = CreateCipher(true);
			CipherStream inCipherStream = new CipherStream(dataStream, inCipher, null);

			int ch;
			while ((ch = inCipherStream.ReadByte()) >= 0)
			{
				encryptedDataStream.WriteByte((byte) ch);
			}

			encryptedDataStream.Close();
			inCipherStream.Close();

			byte[] encryptedDataBytes = encryptedDataStream.ToArray();
			Assert.AreEqual(dataBytes.Length, encryptedDataBytes.Length);

			return encryptedDataBytes;
		}

		private byte[] DecryptOnRead(byte[] encryptedDataBytes)
		{
			MemoryStream encryptedDataStream = new MemoryStream(encryptedDataBytes, false);
			MemoryStream dataStream = new MemoryStream();
			IBufferedCipher inCipher = CreateCipher(false);
			CipherStream inCipherStream = new CipherStream(encryptedDataStream, inCipher, null);

			int ch;
			while ((ch = inCipherStream.ReadByte()) >= 0)
			{
				dataStream.WriteByte((byte) ch);
			}

			inCipherStream.Close();
			dataStream.Close();

			byte[] dataBytes = dataStream.ToArray();
			Assert.AreEqual(encryptedDataBytes.Length, dataBytes.Length);

			return dataBytes;
		}

		private byte[] DecryptOnWrite(byte[] encryptedDataBytes)
		{
			MemoryStream encryptedDataStream = new MemoryStream(encryptedDataBytes, false);
			MemoryStream dataStream = new MemoryStream();
			IBufferedCipher outCipher = CreateCipher(false);
			CipherStream outCipherStream = new CipherStream(dataStream, null, outCipher);

			int ch;
			while ((ch = encryptedDataStream.ReadByte()) >= 0)
			{
				outCipherStream.WriteByte((byte) ch);
			}

			outCipherStream.Close();
			encryptedDataStream.Close();

			byte[] dataBytes = dataStream.ToArray();
			Assert.AreEqual(encryptedDataBytes.Length, dataBytes.Length);

			return dataBytes;
		}

		private IBufferedCipher CreateCipher(bool forEncryption)
		{
//			IBufferedCipher cipher = CipherUtilities.GetCipher("AES/CFB/NoPadding");

			IBlockCipher blockCipher = AesUtilities.CreateEngine();
			int bits = 8 * blockCipher.GetBlockSize(); // TODO Is this right?
			blockCipher = new CfbBlockCipher(blockCipher, bits);
			IBufferedCipher cipher = new BufferedBlockCipher(blockCipher);

//			SecureRandom random = new SecureRandom();
			byte[] keyBytes = new byte[32];
			//random.NextBytes(keyBytes);
			KeyParameter key = new KeyParameter(keyBytes);

			byte[] iv = new byte[cipher.GetBlockSize()];
			//random.NextBytes(iv);

			cipher.Init(forEncryption, new ParametersWithIV(key, iv));

			return cipher;
		}
	}
}
