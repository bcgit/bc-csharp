using System;
using System.Runtime.Serialization;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Tls
{
    /// <summary>Exception for a fatal TLS alert generated locally.</summary>
    [Serializable]
    public class TlsFatalAlert
        : TlsException
    {
        private static string GetMessage(short alertDescription, string detailMessage)
        {
            string msg = Tls.AlertDescription.GetText(alertDescription);
            if (null != detailMessage)
            {
                msg += "; " + detailMessage;
            }
            return msg;
        }

        /// <summary>The alert description.</summary>
        protected readonly byte m_alertDescription;

        /// <summary>Create a new <see cref="TlsFatalAlert"/>.</summary>
        /// <param name="alertDescription">The alert description.</param>
        public TlsFatalAlert(short alertDescription)
            : this(alertDescription, null, null)
        {
        }

        /// <summary>Create a new <see cref="TlsFatalAlert"/>.</summary>
        /// <param name="alertDescription">The alert description.</param>
        /// <param name="detailMessage">The detail message.</param>
        public TlsFatalAlert(short alertDescription, string detailMessage)
            : this(alertDescription, detailMessage, null)
        {
        }

        /// <summary>Create a new <see cref="TlsFatalAlert"/>.</summary>
        /// <param name="alertDescription">The alert description.</param>
        /// <param name="alertCause">The alert cause.</param>
        public TlsFatalAlert(short alertDescription, Exception alertCause)
            : this(alertDescription, null, alertCause)
        {
        }

        /// <summary>Create a new <see cref="TlsFatalAlert"/>.</summary>
        /// <param name="alertDescription">The alert description.</param>
        /// <param name="detailMessage">The detail message.</param>
        /// <param name="alertCause">The alert cause.</param>
        public TlsFatalAlert(short alertDescription, string detailMessage, Exception alertCause)
            : base(GetMessage(alertDescription, detailMessage), alertCause)
        {
            if (!TlsUtilities.IsValidUint8(alertDescription))
                throw new ArgumentOutOfRangeException(nameof(alertDescription));

            m_alertDescription = (byte)alertDescription;
        }

        /// <summary>Create a new <see cref="TlsFatalAlert"/>.</summary>
        /// <param name="info">The serialization information.</param>
        /// <param name="context">The streaming context.</param>
#if NET8_0_OR_GREATER
        [Obsolete(Exceptions.SYSLIB0051_Message, DiagnosticId="SYSLIB0051", UrlFormat="https://aka.ms/dotnet-warnings/{0}")]
#endif
        protected TlsFatalAlert(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
            m_alertDescription = info.GetByte("alertDescription");
        }

        /// <inheritdoc/>
#if NET8_0_OR_GREATER
        [Obsolete(Exceptions.SYSLIB0051_Message, DiagnosticId="SYSLIB0051", UrlFormat="https://aka.ms/dotnet-warnings/{0}")]
#endif
        public override void GetObjectData(SerializationInfo info, StreamingContext context)
        {
            base.GetObjectData(info, context);
            info.AddValue("alertDescription", m_alertDescription);
        }

        /// <summary>Gets the alert description.</summary>
        public virtual short AlertDescription
        {
            get { return m_alertDescription; }
        }
    }
}
