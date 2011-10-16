package org.dcache.xrootd.plugins.alice;

import java.io.File;
import java.io.IOException;

import org.dcache.xrootd2.util.ParseException;

public class TokenAuthorization2Factory extends TokenAuthorization1Factory
{
    final static String NAME = "alice-token-2";

    public TokenAuthorization2Factory(File keystoreFile)
        throws ParseException, IOException
    {
        super(keystoreFile);
    }

    static boolean hasName(String name)
    {
        return NAME.equals(name);
    }

    @Override
    public String getName()
    {
        return NAME;
    }

    @Override
    public String getDescription()
    {
        return "Alice token authorization";
    }

    @Override
    public TokenAuthorization2 createHandler()
    {
        return new TokenAuthorization2(_keystore);
    }
}
