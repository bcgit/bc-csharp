using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Tls.Crypto.Impl
{
    /// <summary>A generic TLS MAC implementation, acting as an HMAC based on some underlying Digest.</summary>
    // TODO[api] sealed
    public class TlsSuiteHmac
        : TlsSuiteMac
    {
        private const long SequenceNumberPlaceholder = -1L;

        protected static int GetMacSize(TlsCryptoParameters cryptoParams, TlsMac mac)
        {
            int macSize = mac.MacLength;
            if (cryptoParams.SecurityParameters.IsTruncatedHmac)
            {
                macSize = System.Math.Min(macSize, 10);
            }
            return macSize;
        }

        protected readonly TlsCryptoParameters m_cryptoParams;
        protected readonly TlsHmac m_mac;
        protected readonly int m_digestBlockSize;
        protected readonly int m_digestOverhead;
        protected readonly int m_macSize;

        /// <summary>Generate a new instance of a TlsMac.</summary>
        /// <param name="cryptoParams">the TLS client context specific crypto parameters.</param>
        /// <param name="mac">The MAC to use.</param>
        public TlsSuiteHmac(TlsCryptoParameters cryptoParams, TlsHmac mac)
        {
            this.m_cryptoParams = cryptoParams;
            this.m_mac = mac;
            this.m_macSize = GetMacSize(cryptoParams, mac);
            this.m_digestBlockSize = mac.InternalBlockSize;

            // TODO This should check the actual algorithm, not assume based on the digest size
            if (TlsImplUtilities.IsSsl(cryptoParams) && mac.MacLength == 20)
            {
                /*
                 * NOTE: For the SSL 3.0 MAC with SHA-1, the secret + input pad is not block-aligned.
                 */
                this.m_digestOverhead = 4;
            }
            else
            {
                this.m_digestOverhead = m_digestBlockSize / 8;
            }
        }

        public virtual int Size
        {
            get { return m_macSize; }
        }

        public virtual byte[] CalculateMac(long seqNo, short type, byte[] msg, int msgOff, int msgLen)
        {
            return CalculateMac(seqNo, type, null, msg, msgOff, msgLen);
        }

        // TODO[api] Replace TlsSuiteMac.CalculateMac (non-span version)
        public virtual byte[] CalculateMac(long seqNo, short type, byte[] connectionID, byte[] msg, int msgOff,
            int msgLen)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            var connIDSpan = connectionID == null ? Span<byte>.Empty : connectionID.AsSpan();

            return CalculateMac(seqNo, type, connIDSpan, msg.AsSpan(msgOff, msgLen));
#else
            ProtocolVersion serverVersion = m_cryptoParams.ServerVersion;

            if (serverVersion.IsSsl)
            {
                byte[] macHeader = new byte[11];
                TlsUtilities.WriteUint64(seqNo, macHeader, 0);
                TlsUtilities.WriteUint8(type, macHeader, 8);
                TlsUtilities.WriteUint16(msgLen, macHeader, 9);

                m_mac.Update(macHeader, 0, macHeader.Length);
            }
            else if (!Arrays.IsNullOrEmpty(connectionID))
            {
                int cidLength = connectionID.Length;
                byte[] macHeader = new byte[23 + cidLength];
                TlsUtilities.WriteUint64(SequenceNumberPlaceholder, macHeader, 0);
                TlsUtilities.WriteUint8(ContentType.tls12_cid, macHeader, 8);
                TlsUtilities.WriteUint8(cidLength, macHeader, 9);
                TlsUtilities.WriteUint8(ContentType.tls12_cid, macHeader, 10);
                TlsUtilities.WriteVersion(serverVersion, macHeader, 11);
                TlsUtilities.WriteUint64(seqNo, macHeader, 13);
                Array.Copy(connectionID, 0, macHeader, 21, cidLength);
                TlsUtilities.WriteUint16(msgLen, macHeader, 21 + cidLength);

                m_mac.Update(macHeader, 0, macHeader.Length);
            }
            else
            {
                byte[] macHeader = new byte[13];
                TlsUtilities.WriteUint64(seqNo, macHeader, 0);
                TlsUtilities.WriteUint8(type, macHeader, 8);
                TlsUtilities.WriteVersion(serverVersion, macHeader, 9);
                TlsUtilities.WriteUint16(msgLen, macHeader, 11);

                m_mac.Update(macHeader, 0, macHeader.Length);
            }

            m_mac.Update(msg, msgOff, msgLen);

            return Truncate(m_mac.CalculateMac());
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public virtual byte[] CalculateMac(long seqNo, short type, ReadOnlySpan<byte> message)
        {
            return CalculateMac(seqNo, type, ReadOnlySpan<byte>.Empty, message);
        }

        // TODO[api] Replace TlsSuiteMac.CalculateMac (span version)
        public virtual byte[] CalculateMac(long seqNo, short type, ReadOnlySpan<byte> connectionID,
            ReadOnlySpan<byte> message)
        {
            ProtocolVersion serverVersion = m_cryptoParams.ServerVersion;

            if (serverVersion.IsSsl)
            {
                byte[] macHeader = new byte[11];
                TlsUtilities.WriteUint64(seqNo, macHeader, 0);
                TlsUtilities.WriteUint8(type, macHeader, 8);
                TlsUtilities.WriteUint16(message.Length, macHeader, 9);

                m_mac.Update(macHeader);
            }
            else if (!connectionID.IsEmpty)
            {
                int cidLength = connectionID.Length;
                byte[] macHeader = new byte[23 + cidLength];
                TlsUtilities.WriteUint64(SequenceNumberPlaceholder, macHeader, 0);
                TlsUtilities.WriteUint8(ContentType.tls12_cid, macHeader, 8);
                TlsUtilities.WriteUint8(cidLength, macHeader, 9);
                TlsUtilities.WriteUint8(ContentType.tls12_cid, macHeader, 10);
                TlsUtilities.WriteVersion(serverVersion, macHeader, 11);
                TlsUtilities.WriteUint64(seqNo, macHeader, 13);
                connectionID.CopyTo(macHeader.AsSpan(21));
                TlsUtilities.WriteUint16(message.Length, macHeader, 21 + cidLength);

                m_mac.Update(macHeader);
            }
            else
            {
                byte[] macHeader = new byte[13];
                TlsUtilities.WriteUint64(seqNo, macHeader, 0);
                TlsUtilities.WriteUint8(type, macHeader, 8);
                TlsUtilities.WriteVersion(serverVersion, macHeader, 9);
                TlsUtilities.WriteUint16(message.Length, macHeader, 11);

                m_mac.Update(macHeader);
            }

            m_mac.Update(message);

            return Truncate(m_mac.CalculateMac());
        }
#endif

        public virtual byte[] CalculateMacConstantTime(long seqNo, short type, byte[] msg, int msgOff, int msgLen,
            int fullLength, byte[] dummyData)
        {
            return CalculateMacConstantTime(seqNo, type, null, msg, msgOff, msgLen, fullLength, dummyData);
        }

        // TODO[api] Replace TlsSuiteMac.CalculateMacConstantTime
        public virtual byte[] CalculateMacConstantTime(long seqNo, short type, byte[] connectionID, byte[] msg,
            int msgOff, int msgLen, int fullLength, byte[] dummyData)
        {
            /*
             * Actual MAC only calculated on 'length' bytes...
             */
            byte[] result = CalculateMac(seqNo, type, connectionID, msg, msgOff, msgLen);

            /*
             * ...but ensure a constant number of complete digest blocks are processed (as many as would
             * be needed for 'fullLength' bytes of input).
             */
            int headerLength = GetHeaderLength(connectionID);

            // How many extra full blocks do we need to calculate?
            int extra = GetDigestBlockCount(headerLength + fullLength) - GetDigestBlockCount(headerLength + msgLen);

            while (--extra >= 0)
            {
                m_mac.Update(dummyData, 0, m_digestBlockSize);
            }

            // One more byte in case the implementation is "lazy" about processing blocks
            m_mac.Update(dummyData, 0, 1);
            m_mac.Reset();

            return result;
        }

        protected virtual int GetDigestBlockCount(int inputLength)
        {
            // NOTE: The input pad for HMAC is always a full digest block

            // NOTE: This calculation assumes a minimum of 1 pad byte
            return (inputLength + m_digestOverhead) / m_digestBlockSize;
        }

        protected virtual int GetHeaderLength(byte[] connectionID)
        {
            if (TlsImplUtilities.IsSsl(m_cryptoParams))
            {
                return 11;
            }
            else if (!Arrays.IsNullOrEmpty(connectionID))
            {
                return 23 + connectionID.Length;
            }
            else
            {
                return 13;
            }
        }

        protected virtual byte[] Truncate(byte[] bs)
        {
            if (bs.Length <= m_macSize)
                return bs;

            return Arrays.CopyOf(bs, m_macSize);
        }
    }
}
