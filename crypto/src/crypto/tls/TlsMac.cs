using System;
using System.IO;
using Org.BouncyCastle.Crypto;
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
        protected TlsContext context;
        protected byte[] secret;
        protected IMac mac;
        protected int digestBlockSize;
        protected int digestOverhead;
        protected int macLength;

        /**
        * Generate a new instance of an TlsMac.
        *
        * @param digest    The digest to use.
        * @param key_block A byte-array where the key for this mac is located.
        * @param offset    The number of bytes to skip, before the key starts in the buffer.
        * @param len       The length of the key.
        */
        public TlsMac(TlsContext context, IDigest digest, byte[] key, int keyOff, int keyLen)
        {
            this.context = context;

            KeyParameter keyParameter = new KeyParameter(key, keyOff, keyLen);

            this.secret = Arrays.Clone(keyParameter.GetKey());

            // TODO This should check the actual algorithm, not rely on the engine type
            if (digest is LongDigest)
            {
                this.digestBlockSize = 128;
                this.digestOverhead = 16;
            }
            else
            {
                this.digestBlockSize = 64;
                this.digestOverhead = 8;
            }

            if (TlsUtilities.IsSSL(context))
            {
                this.mac = new Ssl3Mac(digest);

                // TODO This should check the actual algorithm, not assume based on the digest size
                if (digest.GetDigestSize() == 20)
                {
                    /*
                     * NOTE: When SHA-1 is used with the SSL 3.0 MAC, the secret + input pad is not
                     * digest block-aligned.
                     */
                    this.digestOverhead = 4;
                }
            }
            else
            {
                this.mac = new HMac(digest);

                // NOTE: The input pad for HMAC is always a full digest block
            }

            this.mac.Init(keyParameter);

            this.macLength = mac.GetMacSize();
            if (context.SecurityParameters.truncatedHMac)
            {
                this.macLength = System.Math.Min(this.macLength, 10);
            }
        }

        /**
         * @return the MAC write secret
         */
        public virtual byte[] GetMacSecret()
        {
            return this.secret;
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
        public virtual byte[] CalculateMac(long seqNo, ContentType type, byte[] message, int offset, int length)
        {
            ProtocolVersion serverVersion = context.ServerVersion;
            bool isSSL = serverVersion.IsSSL;

            byte[] macHeader = new byte[isSSL ? 11 : 13];
            TlsUtilities.WriteUint64(seqNo, macHeader, 0);
            TlsUtilities.WriteUint8((byte)type, macHeader, 8);

            if (!isSSL)
            {
                TlsUtilities.WriteVersion(serverVersion, macHeader, 9);
            }

            TlsUtilities.WriteUint16(length, macHeader, macHeader.Length - 2);

            mac.BlockUpdate(macHeader, 0, macHeader.Length);
            mac.BlockUpdate(message, offset, length);

            byte[] result = new byte[mac.GetMacSize()];
            mac.DoFinal(result, 0);
            return Truncate(result);
        }

        public virtual byte[] CalculateMacConstantTime(long seqNo, ContentType type, byte[] message, int offset, int length, int fullLength, byte[] dummyData)
        {
            /*
             * Actual MAC only calculated on 'length' bytes...
             */
            byte[] result = CalculateMac(seqNo, type, message, offset, length);

            /*
             * ...but ensure a constant number of complete digest blocks are processed (as many as would
             * be needed for 'fullLength' bytes of input).
             */
            int headerLength = context.ServerVersion.IsSSL ? 11 : 13;

            // How many extra full blocks do we need to calculate?
            int extra = GetDigestBlockCount(headerLength + fullLength) - GetDigestBlockCount(headerLength + length);

            while (--extra >= 0)
            {
                mac.BlockUpdate(dummyData, 0, digestBlockSize);
            }

            // One more byte in case the implementation is "lazy" about processing blocks
            mac.BlockUpdate(dummyData, 0, dummyData.Length);
            mac.Reset();

            return result;
        }

        protected virtual int GetDigestBlockCount(int inputLength)
        {
            // NOTE: This calculation assumes a minimum of 1 pad byte
            return (inputLength + digestOverhead) / digestBlockSize;
        }

        protected virtual byte[] Truncate(byte[] bs)
        {
            if (bs.Length <= macLength)
            {
                return bs;
            }

            return Arrays.CopyOfRange(bs, 0, macLength);
        }
    }
}
