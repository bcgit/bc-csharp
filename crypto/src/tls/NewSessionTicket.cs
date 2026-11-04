using System.IO;

namespace Org.BouncyCastle.Tls
{
    /// <summary>A NewSessionTicket message.</summary>
    public sealed class NewSessionTicket
    {
        private readonly long m_ticketLifetimeHint;
        private readonly byte[] m_ticket;

        /// <summary>Create a new <see cref="NewSessionTicket"/>.</summary>
        /// <param name="ticketLifetimeHint">The ticket lifetime hint.</param>
        /// <param name="ticket">The ticket.</param>
        public NewSessionTicket(long ticketLifetimeHint, byte[] ticket)
        {
            m_ticketLifetimeHint = ticketLifetimeHint;
            m_ticket = ticket;
        }

        /// <summary>Gets the ticket lifetime hint.</summary>
        public long TicketLifetimeHint => m_ticketLifetimeHint;

        /// <summary>Gets the ticket.</summary>
        public byte[] Ticket => m_ticket;

        /// <summary>Encode this <see cref="NewSessionTicket"/> to a <see cref="Stream"/>.</summary>
        /// <param name="output">the <see cref="Stream"/> to encode to.</param>
        /// <exception cref="IOException"/>
        public void Encode(Stream output)
        {
            TlsUtilities.WriteUint32(TicketLifetimeHint, output);
            TlsUtilities.WriteOpaque16(Ticket, output);
        }

        /// <summary>Parse a <see cref="NewSessionTicket"/> from a <see cref="Stream"/>.</summary>
        /// <param name="input">the <see cref="Stream"/> to parse from.</param>
        /// <returns>a <see cref="NewSessionTicket"/> object.</returns>
        /// <exception cref="IOException"/>
        public static NewSessionTicket Parse(Stream input)
        {
            long ticketLifetimeHint = TlsUtilities.ReadUint32(input);
            byte[] ticket = TlsUtilities.ReadOpaque16(input);
            return new NewSessionTicket(ticketLifetimeHint, ticket);
        }
    }
}
