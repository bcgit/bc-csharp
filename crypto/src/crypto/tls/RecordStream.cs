using System;
using System.IO;

namespace Org.BouncyCastle.Crypto.Tls
{
    /// <remarks>An implementation of the TLS 1.0 record layer.</remarks>
    internal class RecordStream
    {
        private static int DEFAULT_PLAINTEXT_LIMIT = (1 << 14);

        private TlsProtocol handler;
        private Stream input;
        private Stream output;
        private TlsCompression pendingCompression = null, readCompression = null, writeCompression = null;
        private TlsCipher pendingCipher = null, readCipher = null, writeCipher = null;
        private long readSeqNo = 0, writeSeqNo = 0;
        private MemoryStream buffer = new MemoryStream();

        private TlsContext context = null;
        private TlsHandshakeHash hash = null;

        private ProtocolVersion readVersion = null, writeVersion = null;
        private bool restrictReadVersion = true;

        private int plaintextLimit, compressedLimit, ciphertextLimit;

        public RecordStream(TlsProtocol handler, Stream input, Stream output)
        {
            this.handler = handler;
            this.input = input;
            this.output = output;
            this.readCompression = new TlsNullCompression();
            this.writeCompression = this.readCompression;
            this.readCipher = new TlsNullCipher(context);
            this.writeCipher = this.readCipher;

            PlaintextLimit = (DEFAULT_PLAINTEXT_LIMIT);
        }

        internal void Init(TlsContext context)
        {
            this.context = context;
            this.hash = new DeferredHash();
            this.hash.Init(context);
        }

        internal int PlaintextLimit
        {
            get
            {
                return plaintextLimit;
            }
            set
            {
                this.plaintextLimit = value;
                this.compressedLimit = this.plaintextLimit + 1024;
                this.ciphertextLimit = this.compressedLimit + 1024;
            }
        }

        internal ProtocolVersion ReadVersion
        {
            get
            {
                return readVersion;
            }
            set
            {
                this.readVersion = value;
            }
        }

        internal void SetWriteVersion(ProtocolVersion writeVersion)
        {
            this.writeVersion = writeVersion;
        }

        /**
         * RFC 5246 E.1. "Earlier versions of the TLS specification were not fully clear on what the
         * record layer version number (TLSPlaintext.version) should contain when sending ClientHello
         * (i.e., before it is known which version of the protocol will be employed). Thus, TLS servers
         * compliant with this specification MUST accept any value {03,XX} as the record layer version
         * number for ClientHello."
         */
        internal void SetRestrictReadVersion(bool enabled)
        {
            this.restrictReadVersion = enabled;
        }

        internal void NotifyHelloComplete()
        {
            this.hash = this.hash.Commit();
        }

        internal void SetPendingConnectionState(TlsCompression tlsCompression, TlsCipher tlsCipher)
        {
            this.pendingCompression = tlsCompression;
            this.pendingCipher = tlsCipher;
        }

        public void SentWriteCipherSpec()
        {
            if (pendingCompression == null || pendingCipher == null)
            {
                throw new TlsFatalAlert(AlertDescription.handshake_failure);
            }
            this.writeCompression = this.pendingCompression;
            this.writeCipher = this.pendingCipher;
            this.writeSeqNo = 0;
        }

        internal void ReceivedReadCipherSpec()
        {
            if (pendingCompression == null || pendingCipher == null)
            {
                throw new TlsFatalAlert(AlertDescription.handshake_failure);
            }
            this.readCompression = this.pendingCompression;
            this.readCipher = this.pendingCipher;
            this.readSeqNo = 0;
        }

        internal void FinaliseHandshake()
        {
            if (readCompression != pendingCompression || writeCompression != pendingCompression
                || readCipher != pendingCipher || writeCipher != pendingCipher)
            {
                throw new TlsFatalAlert(AlertDescription.handshake_failure);
            }
            pendingCompression = null;
            pendingCipher = null;
        }

        public bool ReadRecord()
        {
            byte[] recordHeader = TlsUtilities.ReadAllOrNothing(5, input);
            if (recordHeader == null)
            {
                return false;
            }

            ContentType type = (ContentType)TlsUtilities.ReadUint8(recordHeader, 0);

            /*
             * RFC 5246 6. If a TLS implementation receives an unexpected record type, it MUST send an
             * unexpected_message alert.
             */
            CheckType(type, AlertDescription.unexpected_message);

            if (!restrictReadVersion)
            {
                int version = TlsUtilities.ReadVersionRaw(recordHeader, 1);
                if ((version & 0xffffff00) != 0x0300)
                {
                    throw new TlsFatalAlert(AlertDescription.illegal_parameter);
                }
            }
            else
            {
                ProtocolVersion version = TlsUtilities.ReadVersion(recordHeader, 1);
                if (readVersion == null)
                {
                    readVersion = version;
                }
                else if (!version.Equals(readVersion))
                {
                    throw new TlsFatalAlert(AlertDescription.illegal_parameter);
                }
            }

            int length = TlsUtilities.ReadUint16(recordHeader, 3);
            byte[] plaintext = DecodeAndVerify(type, input, length);
            handler.ProcessRecord(type, plaintext, 0, plaintext.Length);
            return true;
        }

        protected byte[] DecodeAndVerify(ContentType type, Stream input, int len)
        {
            CheckLength(len, ciphertextLimit, AlertDescription.record_overflow);

            byte[] buf = TlsUtilities.ReadFully(len, input);
            byte[] decoded = readCipher.DecodeCiphertext(readSeqNo++, type, buf, 0, buf.Length);

            CheckLength(decoded.Length, compressedLimit, AlertDescription.record_overflow);

            /*
             * TODO RFC5264 6.2.2. Implementation note: Decompression functions are responsible for
             * ensuring that messages cannot cause internal buffer overflows.
             */
            Stream cOut = readCompression.Decompress(buffer);
            if (cOut != buffer)
            {
                cOut.Write(decoded, 0, decoded.Length);
                cOut.Flush();
                decoded = GetBufferContents();
            }

            /*
             * RFC 5264 6.2.2. If the decompression function encounters a TLSCompressed.fragment that
             * would decompress to a length in excess of 2^14 bytes, it should report a fatal
             * decompression failure error.
             */
            CheckLength(decoded.Length, plaintextLimit, AlertDescription.decompression_failure);

            /*
             * RFC 5264 6.2.1 Implementations MUST NOT send zero-length fragments of Handshake, Alert,
             * or ChangeCipherSpec content types.
             */
            if (decoded.Length < 1 && type != ContentType.application_data)
            {
                throw new TlsFatalAlert(AlertDescription.illegal_parameter);
            }

            return decoded;
        }

        protected internal void WriteRecord(ContentType type, byte[] plaintext, int plaintextOffset, int plaintextLength)
        {
            /*
             * RFC 5264 6. Implementations MUST NOT send record types not defined in this document
             * unless negotiated by some extension.
             */
            CheckType(type, AlertDescription.internal_error);

            /*
             * RFC 5264 6.2.1 The length should not exceed 2^14.
             */
            CheckLength(plaintextLength, plaintextLimit, AlertDescription.internal_error);

            /*
             * RFC 5264 6.2.1 Implementations MUST NOT send zero-length fragments of Handshake, Alert,
             * or ChangeCipherSpec content types.
             */
            if (plaintextLength < 1 && type != ContentType.application_data)
            {
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }

            if (type == ContentType.handshake)
            {
                UpdateHandshakeData(plaintext, plaintextOffset, plaintextLength);
            }

            Stream cOut = writeCompression.Compress(buffer);            

            byte[] ciphertext;
            if (cOut == buffer)
            {
                ciphertext = writeCipher.EncodePlaintext(writeSeqNo++, type, plaintext, plaintextOffset, plaintextLength, 5);
            }
            else
            {
                cOut.Write(plaintext, plaintextOffset, plaintextLength);
                cOut.Flush();
                byte[] compressed = GetBufferContents();

                /*
                 * RFC5264 6.2.2. Compression must be lossless and may not increase the content length
                 * by more than 1024 bytes.
                 */
                CheckLength(compressed.Length, plaintextLength + 1024, AlertDescription.internal_error);

                ciphertext = writeCipher.EncodePlaintext(writeSeqNo++, type, compressed, 0, compressed.Length, 5);
            }

            /*
             * RFC 5264 6.2.3. The length may not exceed 2^14 + 2048.
             */
            CheckLength(ciphertext.Length - 5, ciphertextLimit, AlertDescription.internal_error);

            byte[] record = ciphertext;
            TlsUtilities.WriteUint8((byte)type, record, 0);
            TlsUtilities.WriteVersion(writeVersion, record, 1);
            TlsUtilities.WriteUint16(ciphertext.Length - 5, record, 3);
            //Buffer.BlockCopy(ciphertext, 0, record, 5, ciphertext.Length);
            output.Write(record, 0, record.Length);
            output.Flush();
        }

        internal void UpdateHandshakeData(byte[] message, int offset, int len)
        {
            hash.BlockUpdate(message, offset, len);
        }

        /**
         * 'sender' only relevant to SSLv3
         */
        internal byte[] GetCurrentHash(byte[] sender)
        {
            TlsHandshakeHash d = hash.Fork();

            if (context.ServerVersion.IsSSL)
            {
                if (sender != null)
                {
                    d.BlockUpdate(sender, 0, sender.Length);
                }
            }

            return DoFinal(d);
        }

        protected internal void SafeClose()
        {
            try
            {
                input.Close();
            }
            catch 
            {
            }

            try
            {
                output.Close();
            }
            catch 
            {
            }
        }

        protected internal void Flush()
        {
            output.Flush();
        }

        private byte[] GetBufferContents()
        {
            byte[] contents = buffer.ToArray();
            buffer.SetLength(0); 
            return contents;
        }

        private static byte[] DoFinal(IDigest d)
        {
            byte[] bs = new byte[d.GetDigestSize()];
            d.DoFinal(bs, 0);
            return bs;
        }

        private static void CheckType(ContentType type, AlertDescription alertDescription)
        {
            switch (type)
            {
                case ContentType.application_data:
                case ContentType.alert:
                case ContentType.change_cipher_spec:
                case ContentType.handshake:
                case ContentType.heartbeat:
                    break;
                default:
                    throw new TlsFatalAlert(alertDescription);
            }
        }

        private static void CheckLength(int length, int limit, AlertDescription alertDescription)
        {
            if (length > limit)
            {
                throw new TlsFatalAlert(alertDescription);
            }
        }
    }
}
    
