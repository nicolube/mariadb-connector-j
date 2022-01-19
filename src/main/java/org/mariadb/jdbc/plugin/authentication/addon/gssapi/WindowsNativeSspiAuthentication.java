// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2012-2014 Monty Program Ab
// Copyright (c) 2015-2021 MariaDB Corporation Ab

package org.mariadb.jdbc.plugin.authentication.addon.gssapi;

import com.sun.jna.platform.win32.Sspi;
import com.sun.jna.platform.win32.SspiUtil;
import java.io.IOException;
import org.mariadb.jdbc.client.ReadableByteBuf;
import org.mariadb.jdbc.client.socket.Reader;
import org.mariadb.jdbc.client.socket.Writer;
import waffle.windows.auth.IWindowsSecurityContext;
import waffle.windows.auth.impl.WindowsSecurityContextImpl;

/** Waffle windows GSSAPI implementation */
public class WindowsNativeSspiAuthentication implements GssapiAuth {

  /**
   * Process native windows GSS plugin authentication.
   *
   * @param out out stream
   * @param in in stream
   * @param servicePrincipalName principal name
   * @param mechanisms gssapi mechanism
   * @throws IOException if socket error
   */
  public void authenticate(
      final Writer out, final Reader in, final String servicePrincipalName, final String mechanisms)
      throws IOException {

    // initialize a security context on the client
    IWindowsSecurityContext clientContext =
        WindowsSecurityContextImpl.getCurrent(mechanisms, servicePrincipalName);

    do {

      // Step 1: send token to server
      byte[] tokenForTheServerOnTheClient = clientContext.getToken();
      out.writeBytes(tokenForTheServerOnTheClient);
      out.flush();

      // Step 2: read server response token
      if (clientContext.isContinue()) {
        ReadableByteBuf buf = in.readPacket(true);
        byte[] tokenForTheClientOnTheServer = new byte[buf.readableBytes()];
        buf.readBytes(tokenForTheClientOnTheServer);
        Sspi.SecBufferDesc continueToken =
            new SspiUtil.ManagedSecBufferDesc(Sspi.SECBUFFER_TOKEN, tokenForTheClientOnTheServer);
        clientContext.initialize(clientContext.getHandle(), continueToken, servicePrincipalName);
      }

    } while (clientContext.isContinue());

    clientContext.dispose();
  }
}
