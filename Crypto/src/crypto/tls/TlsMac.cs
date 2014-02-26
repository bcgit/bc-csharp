using System;
using System.IO;

using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Tls
{
	/// <remarks>
	/// A generic TLS MAC implementation, which can be used with any kind of
	/// IDigest to act as an HMAC.
	/// </remarks>
	public class TlsMac
	{
		protected long seqNo;
		protected byte[] secret;
		protected HMac mac;

		/**
		* Generate a new instance of an TlsMac.
		*
		* @param digest    The digest to use.
		* @param key_block A byte-array where the key for this mac is located.
		* @param offset    The number of bytes to skip, before the key starts in the buffer.
		* @param len       The length of the key.
		*/
		public TlsMac(
			IDigest	digest,
			byte[]	key_block,
			int		offset,
			int		len)
		{
			this.seqNo = 0;

			KeyParameter param = new KeyParameter(key_block, offset, len);

			this.secret = Arrays.Clone(param.GetKey());

			this.mac = new HMac(digest);
			this.mac.Init(param);
		}

		/**
		 * @return the MAC write secret
		 */
		public virtual byte[] GetMacSecret()
		{
			return this.secret;
		}

		/**
		 * @return the current write sequence number
		 */
		public virtual long SequenceNumber
		{
			get { return this.seqNo; }
		}

		/**
		 * Increment the current write sequence number
		 */
		public virtual void IncSequenceNumber()
		{
			this.seqNo++;
		}

		/**
		* @return The Keysize of the mac.
		*/
		public virtual int Size
		{
			get { return mac.GetMacSize(); }
		}

		/**
		* Calculate the mac for some given data.
		* <p/>
		* TlsMac will keep track of the sequence number internally.
		*
		* @param type    The message type of the message.
		* @param message A byte-buffer containing the message.
		* @param offset  The number of bytes to skip, before the message starts.
		* @param len     The length of the message.
		* @return A new byte-buffer containing the mac value.
		*/
		public virtual byte[] CalculateMac(
			ContentType	type,
			byte[]		message,
			int			offset,
			int			len)
		{
			byte[] macHeader = new byte[13];
			TlsUtilities.WriteUint64(seqNo++, macHeader, 0);
			TlsUtilities.WriteUint8((byte)type, macHeader, 8);
			TlsUtilities.WriteVersion(macHeader, 9);
			TlsUtilities.WriteUint16(len, macHeader, 11);

			mac.BlockUpdate(macHeader, 0, macHeader.Length);
			mac.BlockUpdate(message, offset, len);
			return MacUtilities.DoFinal(mac);
		}
	}
}
