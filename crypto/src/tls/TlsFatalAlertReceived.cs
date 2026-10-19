using System;
using System.Runtime.Serialization;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Tls
{
    /// <summary>Exception for a fatal TLS alert received from the peer.</summary>
    [Serializable]
    public class TlsFatalAlertReceived
        : TlsException
    {
        protected readonly byte m_alertDescription;

        /// <summary>Create a new <see cref="TlsFatalAlertReceived"/>.</summary>
        /// <param name="alertDescription">The alert description.</param>
        public TlsFatalAlertReceived(short alertDescription)
            : base(Tls.AlertDescription.GetText(alertDescription))
        {
            if (!TlsUtilities.IsValidUint8(alertDescription))
                throw new ArgumentOutOfRangeException(nameof(alertDescription));

            m_alertDescription = (byte)alertDescription;
        }

        /// <summary>Create a new <see cref="TlsFatalAlertReceived"/>.</summary>
        /// <param name="info">The info.</param>
        /// <param name="context">The context.</param>
#if NET8_0_OR_GREATER
        [Obsolete(Exceptions.SYSLIB0051_Message, DiagnosticId="SYSLIB0051", UrlFormat="https://aka.ms/dotnet-warnings/{0}")]
#endif
        protected TlsFatalAlertReceived(SerializationInfo info, StreamingContext context)
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
