using System;
using System.IO;
using System.Net.Sockets;

namespace Org.BouncyCastle.Tls
{
    [Flags]
    public enum DtlsRecordFlags
    {
        None = 0,

        /// <summary>The record is newer (by epoch and sequence number) than any record received previously.</summary>
        IsNewest = 1,

        /// <summary>The record includes the (valid) connection ID (RFC 9146) for this connection.</summary>
        UsesConnectionID = 2,
    }

    public delegate void DtlsRecordCallback(DtlsRecordFlags flags);

    public class DtlsTransport
        : DatagramTransport
    {
        private readonly DtlsRecordLayer m_recordLayer;
        private readonly bool m_ignoreCorruptRecords;

        internal DtlsTransport(DtlsRecordLayer recordLayer, bool ignoreCorruptRecords)
        {
            m_recordLayer = recordLayer;
            m_ignoreCorruptRecords = ignoreCorruptRecords;
        }

        /// <exception cref="IOException"/>
        public virtual int GetReceiveLimit()
        {
            return m_recordLayer.GetReceiveLimit();
        }

        /// <exception cref="IOException"/>
        public virtual int GetSendLimit()
        {
            return m_recordLayer.GetSendLimit();
        }

        /// <exception cref="IOException"/>
        public virtual int Receive(byte[] buf, int off, int len, int waitMillis)
        {
            return Receive(buf, off, len, waitMillis, null);
        }

        // TODO[api] Add to DatagramTransport (with a default null parameter)
        /// <exception cref="IOException"/>
        public virtual int Receive(byte[] buf, int off, int len, int waitMillis, DtlsRecordCallback recordCallback)
        {
            if (null == buf)
                throw new ArgumentNullException("buf");
            if (off < 0 || off >= buf.Length)
                throw new ArgumentException("invalid offset: " + off, "off");
            if (len < 0 || len > buf.Length - off)
                throw new ArgumentException("invalid length: " + len, "len");

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            return Receive(buf.AsSpan(off, len), waitMillis, recordCallback);
#else
            if (waitMillis < 0)
                throw new ArgumentException("cannot be negative", "waitMillis");

            try
            {
                return m_recordLayer.Receive(buf, off, len, waitMillis, recordCallback);
            }
            catch (TlsFatalAlert fatalAlert)
            {
                if (m_ignoreCorruptRecords && AlertDescription.bad_record_mac == fatalAlert.AlertDescription)
                    return -1;

                m_recordLayer.Fail(fatalAlert.AlertDescription);
                throw;
            }
            catch (TlsTimeoutException)
            {
                throw;
            }
            catch (SocketException e)
            {
                if (TlsUtilities.IsTimeout(e))
                    throw;

                m_recordLayer.Fail(AlertDescription.internal_error);
                throw new TlsFatalAlert(AlertDescription.internal_error, e);
            }
            // TODO[tls-port] Can we support interrupted IO on .NET?
            //catch (InterruptedIOException)
            //{
            //    throw;
            //}
            catch (IOException)
            {
                m_recordLayer.Fail(AlertDescription.internal_error);
                throw;
            }
            catch (Exception e)
            {
                m_recordLayer.Fail(AlertDescription.internal_error);
                throw new TlsFatalAlert(AlertDescription.internal_error, e);
            }
#endif
        }

        // TODO[api] Add to DatagramTransport
        /// <exception cref="IOException"/>
        public virtual int ReceivePending(byte[] buf, int off, int len, DtlsRecordCallback recordCallback = null)
        {
            if (null == buf)
                throw new ArgumentNullException("buf");
            if (off < 0 || off >= buf.Length)
                throw new ArgumentException("invalid offset: " + off, "off");
            if (len < 0 || len > buf.Length - off)
                throw new ArgumentException("invalid length: " + len, "len");

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            return ReceivePending(buf.AsSpan(off, len), recordCallback);
#else
            try
            {
                return m_recordLayer.ReceivePending(buf, off, len, recordCallback);
            }
            catch (TlsFatalAlert fatalAlert)
            {
                if (m_ignoreCorruptRecords && AlertDescription.bad_record_mac == fatalAlert.AlertDescription)
                    return -1;

                m_recordLayer.Fail(fatalAlert.AlertDescription);
                throw;
            }
            catch (TlsTimeoutException)
            {
                throw;
            }
            catch (SocketException e)
            {
                if (TlsUtilities.IsTimeout(e))
                    throw;

                m_recordLayer.Fail(AlertDescription.internal_error);
                throw new TlsFatalAlert(AlertDescription.internal_error, e);
            }
            // TODO[tls-port] Can we support interrupted IO on .NET?
            //catch (InterruptedIOException)
            //{
            //    throw;
            //}
            catch (IOException)
            {
                m_recordLayer.Fail(AlertDescription.internal_error);
                throw;
            }
            catch (Exception e)
            {
                m_recordLayer.Fail(AlertDescription.internal_error);
                throw new TlsFatalAlert(AlertDescription.internal_error, e);
            }
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <exception cref="IOException"/>
        public virtual int Receive(Span<byte> buffer, int waitMillis)
        {
            return Receive(buffer, waitMillis, null);
        }

        // TODO[api] Add to DatagramTransport (with a default null parameter)
        /// <exception cref="IOException"/>
        public virtual int Receive(Span<byte> buffer, int waitMillis, DtlsRecordCallback recordCallback)
        {
            if (waitMillis < 0)
                throw new ArgumentException("cannot be negative", nameof(waitMillis));

            try
            {
                return m_recordLayer.Receive(buffer, waitMillis, recordCallback);
            }
            catch (TlsFatalAlert fatalAlert)
            {
                if (m_ignoreCorruptRecords && AlertDescription.bad_record_mac == fatalAlert.AlertDescription)
                    return -1;

                m_recordLayer.Fail(fatalAlert.AlertDescription);
                throw;
            }
            catch (TlsTimeoutException)
            {
                throw;
            }
            catch (SocketException e)
            {
                if (TlsUtilities.IsTimeout(e))
                    throw;

                m_recordLayer.Fail(AlertDescription.internal_error);
                throw new TlsFatalAlert(AlertDescription.internal_error, e);
            }
            // TODO[tls-port] Can we support interrupted IO on .NET?
            //catch (InterruptedIOException)
            //{
            //    throw;
            //}
            catch (IOException)
            {
                m_recordLayer.Fail(AlertDescription.internal_error);
                throw;
            }
            catch (Exception e)
            {
                m_recordLayer.Fail(AlertDescription.internal_error);
                throw new TlsFatalAlert(AlertDescription.internal_error, e);
            }
        }

        // TODO[api] Add to DatagramTransport
        /// <exception cref="IOException"/>
        public virtual int ReceivePending(Span<byte> buffer, DtlsRecordCallback recordCallback = null)
        {
            try
            {
                return m_recordLayer.ReceivePending(buffer, recordCallback);
            }
            catch (TlsFatalAlert fatalAlert)
            {
                if (m_ignoreCorruptRecords && AlertDescription.bad_record_mac == fatalAlert.AlertDescription)
                    return -1;

                m_recordLayer.Fail(fatalAlert.AlertDescription);
                throw;
            }
            catch (TlsTimeoutException)
            {
                throw;
            }
            catch (SocketException e)
            {
                if (TlsUtilities.IsTimeout(e))
                    throw;

                m_recordLayer.Fail(AlertDescription.internal_error);
                throw new TlsFatalAlert(AlertDescription.internal_error, e);
            }
            // TODO[tls-port] Can we support interrupted IO on .NET?
            //catch (InterruptedIOException)
            //{
            //    throw;
            //}
            catch (IOException)
            {
                m_recordLayer.Fail(AlertDescription.internal_error);
                throw;
            }
            catch (Exception e)
            {
                m_recordLayer.Fail(AlertDescription.internal_error);
                throw new TlsFatalAlert(AlertDescription.internal_error, e);
            }
        }
#endif

        /// <exception cref="IOException"/>
        public virtual void Send(byte[] buf, int off, int len)
        {
            if (null == buf)
                throw new ArgumentNullException("buf");
            if (off < 0 || off >= buf.Length)
                throw new ArgumentException("invalid offset: " + off, "off");
            if (len < 0 || len > buf.Length - off)
                throw new ArgumentException("invalid length: " + len, "len");

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Send(buf.AsSpan(off, len));
#else
            try
            {
                m_recordLayer.Send(buf, off, len);
            }
            catch (TlsFatalAlert fatalAlert)
            {
                m_recordLayer.Fail(fatalAlert.AlertDescription);
                throw;
            }
            catch (TlsTimeoutException)
            {
                throw;
            }
            catch (SocketException e)
            {
                if (TlsUtilities.IsTimeout(e))
                    throw;

                m_recordLayer.Fail(AlertDescription.internal_error);
                throw new TlsFatalAlert(AlertDescription.internal_error, e);
            }
            // TODO[tls-port] Can we support interrupted IO on .NET?
            //catch (InterruptedIOException)
            //{
            //    throw;
            //}
            catch (IOException)
            {
                m_recordLayer.Fail(AlertDescription.internal_error);
                throw;
            }
            catch (Exception e)
            {
                m_recordLayer.Fail(AlertDescription.internal_error);
                throw new TlsFatalAlert(AlertDescription.internal_error, e);
            }
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public virtual void Send(ReadOnlySpan<byte> buffer)
        {
            try
            {
                m_recordLayer.Send(buffer);
            }
            catch (TlsFatalAlert fatalAlert)
            {
                m_recordLayer.Fail(fatalAlert.AlertDescription);
                throw;
            }
            catch (TlsTimeoutException)
            {
                throw;
            }
            catch (SocketException e)
            {
                if (TlsUtilities.IsTimeout(e))
                    throw;

                m_recordLayer.Fail(AlertDescription.internal_error);
                throw new TlsFatalAlert(AlertDescription.internal_error, e);
            }
            // TODO[tls-port] Can we support interrupted IO on .NET?
            //catch (InterruptedIOException)
            //{
            //    throw;
            //}
            catch (IOException)
            {
                m_recordLayer.Fail(AlertDescription.internal_error);
                throw;
            }
            catch (Exception e)
            {
                m_recordLayer.Fail(AlertDescription.internal_error);
                throw new TlsFatalAlert(AlertDescription.internal_error, e);
            }
        }
#endif

        /// <exception cref="IOException"/>
        public virtual void Close()
        {
            m_recordLayer.Close();
        }
    }
}
