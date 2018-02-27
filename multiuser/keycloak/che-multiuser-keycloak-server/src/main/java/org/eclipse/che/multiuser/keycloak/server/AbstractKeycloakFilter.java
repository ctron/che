/*
 * Copyright (c) 2012-2018 Red Hat, Inc.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Contributors:
 *   Red Hat, Inc. - initial API and implementation
 */
package org.eclipse.che.multiuser.keycloak.server;

import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.Jwts;
import java.security.PublicKey;
import javax.inject.Inject;
import javax.servlet.Filter;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import org.eclipse.che.multiuser.machine.authentication.server.SignatureKeyManager;

/**
 * Base abstract class for the Keycloak-related servlet filters.
 *
 * <p>In particular it defines commnon use-cases when the authentication / multi-user logic should
 * be skipped
 */
public abstract class AbstractKeycloakFilter implements Filter {

  private static final String MACHINE_TOKEN_KIND = "machine_token";

  @Inject private SignatureKeyManager signatureKeyManager;

  protected boolean shouldSkipAuthentication(HttpServletRequest request, String token) {
    try {
      final PublicKey signatureKey = signatureKeyManager.getKeyPair().getPublic();
      final Jwt jwt = Jwts.parser().setSigningKey(signatureKey).parse(token);
      return request.getScheme().startsWith("ws")
          || (token != null && MACHINE_TOKEN_KIND.equals(jwt.getHeader().get("kind")));
    } catch (RuntimeException ex) {
      // give token is not signed by particular signature key so it must be checked in another way
      return false;
    }
  }

  @Override
  public void init(FilterConfig filterConfig) throws ServletException {}

  @Override
  public void destroy() {}
}
