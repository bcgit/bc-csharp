using System;
using System.IO;
using System.Runtime.ExceptionServices;

using NUnit.Framework;

namespace Org.BouncyCastle.Tls.Tests
{
    /// <summary>The outcome of one loopback run, as seen from both ends of the connection.</summary>
    /// <remarks>
    /// Both raw exceptions are kept. A test that expects a particular end to fail should look at that end's
    /// exception directly; <see cref="PrimaryException"/> and <see cref="ThrowIfFailed"/> serve the common case where
    /// any failure is unexpected and the most informative report of it is wanted.
    /// </remarks>
    internal sealed class LoopbackResult
    {
        internal Exception ClientException;
        internal Exception ServerException;

        /// <summary>Whether the client's transport stream had been closed by the end of the run (TLS only).</summary>
        internal bool ClientStreamClosed;

        /// <summary>Whether the server's transport stream had been closed by the end of the run (TLS only).</summary>
        internal bool ServerStreamClosed;

        internal bool Failed => ClientException != null || ServerException != null;

        /// <summary>The exception that best explains a failed run, or null if the run succeeded.</summary>
        /// <remarks>
        /// When only one end failed, that end's exception. When both failed, the end that decided to fail (raised a
        /// fatal alert, timed out) is preferred over the end that merely received the alert or saw the connection
        /// close under it, and a test-logic failure (e.g. a failed assertion in a callback) is preferred over either.
        /// Ties go to the server, whose exception usually carries the detail the client's internal_error lacks.
        /// </remarks>
        internal Exception PrimaryException
        {
            get
            {
                if (ClientException == null || ServerException == null)
                    return ClientException ?? ServerException;

                return Rank(ClientException) > Rank(ServerException) ? ClientException : ServerException;
            }
        }

        /// <summary>Rethrow <see cref="PrimaryException"/>, keeping its stack trace, if the run failed.</summary>
        internal void ThrowIfFailed()
        {
            Exception primary = PrimaryException;
            if (primary != null)
            {
                ExceptionDispatchInfo.Capture(primary).Throw();
            }
        }

        /// <summary>Assert that the client failed because it received the given fatal alert from the server.</summary>
        internal void AssertClientReceivedFatalAlert(short alertDescription)
        {
            Assert.IsInstanceOf<TlsFatalAlertReceived>(ClientException, "client did not receive a fatal alert");
            Assert.AreEqual(alertDescription, ((TlsFatalAlertReceived)ClientException).AlertDescription,
                "client received the wrong fatal alert");
        }

        private static int Rank(Exception e)
        {
            // The victim of the other end's failure (TlsNoCloseNotifyException is an EndOfStreamException)
            if (e is TlsFatalAlertReceived || e is EndOfStreamException || e is ObjectDisposedException)
                return 0;

            // The end that decided to fail: TlsFatalAlert, TlsTimeoutException, other transport failures
            if (e is IOException)
                return 1;

            // Test logic: a failed assertion, an InvalidOperationException from a callback, ...
            return 2;
        }
    }
}
