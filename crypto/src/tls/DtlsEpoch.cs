﻿using System;
using System.IO;

using Org.BouncyCastle.Tls.Crypto;

namespace Org.BouncyCastle.Tls
{
    internal sealed class DtlsEpoch
    {
        private readonly DtlsReplayWindow m_replayWindow = new DtlsReplayWindow();

        private readonly int m_epoch;
        private readonly TlsCipher m_cipher;
        private readonly int m_recordHeaderLengthRead, m_recordHeaderLengthWrite;

        private long m_sequenceNumber = 0;

        internal DtlsEpoch(int epoch, TlsCipher cipher, int recordHeaderLengthRead, int recordHeaderLengthWrite)
        {
            if (epoch < 0)
                throw new ArgumentException("must be >= 0", "epoch");
            if (cipher == null)
                throw new ArgumentNullException("cipher");

            this.m_epoch = epoch;
            this.m_cipher = cipher;
            this.m_recordHeaderLengthRead = recordHeaderLengthRead;
            this.m_recordHeaderLengthWrite = recordHeaderLengthWrite;
        }

        /// <exception cref="IOException"/>
        internal long AllocateSequenceNumber()
        {
            lock (this)
            {
                if (m_sequenceNumber >= (1L << 48))
                    throw new TlsFatalAlert(AlertDescription.internal_error);

                return m_sequenceNumber++;
            }
        }

        internal TlsCipher Cipher
        {
            get { return m_cipher; }
        }

        internal int Epoch
        {
            get { return m_epoch; }
        }

        internal int RecordHeaderLengthRead => m_recordHeaderLengthRead;

        internal int RecordHeaderLengthWrite => m_recordHeaderLengthWrite;

        internal DtlsReplayWindow ReplayWindow
        {
            get { return m_replayWindow; }
        }

        internal long SequenceNumber
        {
            get { lock (this) return m_sequenceNumber; }
            set { lock (this) this.m_sequenceNumber = value; }
        }
    }
}
