using System;
using System.IO;
#if !PORTABLE || DOTNET
using System.Net.Sockets;
#endif

namespace Org.BouncyCastle.Crypto.Tls
{
    public class DtlsTransport
        :   DatagramTransport
    {
        private readonly DtlsRecordLayer mRecordLayer;

        internal DtlsTransport(DtlsRecordLayer recordLayer)
        {
            this.mRecordLayer = recordLayer;
        }

        public virtual int GetReceiveLimit()
        {
            return mRecordLayer.GetReceiveLimit();
        }

        public virtual int GetSendLimit()
        {
            return mRecordLayer.GetSendLimit();
        }

        public virtual int Receive(byte[] buf, int off, int len, int waitMillis)
        {
            if (null == buf)
                throw new ArgumentNullException("buf");
            if (off < 0 || off >= buf.Length)
                throw new ArgumentException("invalid offset: " + off, "off");
            if (len < 0 || len > buf.Length - off)
                throw new ArgumentException("invalid length: " + len, "len");
            if (waitMillis < 0)
                throw new ArgumentException("cannot be negative", "waitMillis");

            try
            {
                return mRecordLayer.Receive(buf, off, len, waitMillis);
            }
            catch (TlsFatalAlert fatalAlert)
            {
                mRecordLayer.Fail(fatalAlert.AlertDescription);
                throw fatalAlert;
            }
            catch (TlsTimeoutException e)
            {
                throw e;
            }
#if !PORTABLE || DOTNET
            catch (SocketException e)
            {
                if (TlsUtilities.IsTimeout(e))
                    throw e;

                mRecordLayer.Fail(AlertDescription.internal_error);
                throw new TlsFatalAlert(AlertDescription.internal_error, e);
            }
#endif
            //catch (InterruptedIOException e)
            //{
            //    throw e;
            //}
            catch (IOException e)
            {
                mRecordLayer.Fail(AlertDescription.internal_error);
                throw e;
            }
            catch (Exception e)
            {
                mRecordLayer.Fail(AlertDescription.internal_error);
                throw new TlsFatalAlert(AlertDescription.internal_error, e);
            }
        }

        public virtual void Send(byte[] buf, int off, int len)
        {
            if (null == buf)
                throw new ArgumentNullException("buf");
            if (off < 0 || off >= buf.Length)
                throw new ArgumentException("invalid offset: " + off, "off");
            if (len < 0 || len > buf.Length - off)
                throw new ArgumentException("invalid length: " + len, "len");

            try
            {
                mRecordLayer.Send(buf, off, len);
            }
            catch (TlsFatalAlert fatalAlert)
            {
                mRecordLayer.Fail(fatalAlert.AlertDescription);
                throw fatalAlert;
            }
            catch (TlsTimeoutException e)
            {
                throw e;
            }
#if !PORTABLE || DOTNET
            catch (SocketException e)
            {
                if (TlsUtilities.IsTimeout(e))
                    throw e;

                mRecordLayer.Fail(AlertDescription.internal_error);
                throw new TlsFatalAlert(AlertDescription.internal_error, e);
            }
#endif
            //catch (InterruptedIOException e)
            //{
            //    throw e;
            //}
            catch (IOException e)
            {
                mRecordLayer.Fail(AlertDescription.internal_error);
                throw e;
            }
            catch (Exception e)
            {
                mRecordLayer.Fail(AlertDescription.internal_error);
                throw new TlsFatalAlert(AlertDescription.internal_error, e);
            }
        }

        public virtual void Close()
        {
            mRecordLayer.Close();
        }
    }
}
