package org.dcache.xrootd.plugins.alice;

import java.util.Properties;
import java.io.File;
import java.io.IOException;

import org.dcache.xrootd.plugins.AuthorizationProvider;
import org.dcache.xrootd.plugins.AuthorizationFactory;
import org.dcache.xrootd.util.ParseException;

public class TokenAuthorizationProvider implements AuthorizationProvider
{
    @Override
    public AuthorizationFactory
        createFactory(String plugin, Properties properties)
        throws ParseException, IOException
    {
        if (TokenAuthorization1Factory.hasName(plugin)) {
            String file = properties.getProperty("xrootdAuthzKeystore");
            return new TokenAuthorization1Factory(new File(file));
        }
        return null;
    }
}