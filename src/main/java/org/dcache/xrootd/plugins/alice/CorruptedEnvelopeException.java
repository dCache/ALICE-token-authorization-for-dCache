package org.dcache.xrootd.plugins.alice;

public class CorruptedEnvelopeException extends Exception
{
    public CorruptedEnvelopeException(String message) {
        super(message);
    }

    public CorruptedEnvelopeException(Throwable cause) {
        super(cause);
    }

    public CorruptedEnvelopeException(String message, Throwable cause) {
        super(message, cause);
    }
}
