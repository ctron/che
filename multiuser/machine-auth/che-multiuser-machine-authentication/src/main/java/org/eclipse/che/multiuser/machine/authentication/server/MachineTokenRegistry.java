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
package org.eclipse.che.multiuser.machine.authentication.server;

import static io.jsonwebtoken.SignatureAlgorithm.RS512;

import com.google.common.collect.HashBasedTable;
import com.google.common.collect.Table;
import com.google.gson.Gson;
import io.jsonwebtoken.Jwts;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import javax.inject.Inject;
import javax.inject.Singleton;
import org.eclipse.che.commons.env.EnvironmentContext;
import org.eclipse.che.commons.subject.Subject;
import org.eclipse.che.commons.subject.SubjectImpl;

/**
 * Table-based storage of machine security tokens. Table rows is workspace id's, columns - user
 * id's. Table is synchronized externally as required by its javadoc.
 *
 * @author Max Shaposhnik (mshaposhnik@codenvy.com)
 * @see HashBasedTable
 */
@Singleton
public class MachineTokenRegistry {

  public static final String MACHINE_TOKEN_KIND = "machine_token";

  private static final Gson GSON = new Gson();

  private final SignatureKeyManager signatureKeyManager;
  private final Table<String, String, String> tokens;
  private final ReadWriteLock lock;

  @Inject
  public MachineTokenRegistry(SignatureKeyManager signatureKeyManager) {
    this.signatureKeyManager = signatureKeyManager;
    this.tokens = HashBasedTable.create();
    this.lock = new ReentrantReadWriteLock();
  }

  /**
   * Gets or creates machine security token for user and workspace. For running workspace, there is
   * always at least one token for user who performed start.
   *
   * @param userId id of user to get token
   * @param workspaceId id of workspace to get token
   * @return machine security token for for given user and workspace
   */
  public String getOrCreateToken(String userId, String workspaceId) {
    lock.writeLock().lock();
    try {
      final Map<String, String> wsRow = tokens.row(workspaceId);
      String token = wsRow.get(userId);

      if (token == null) {
        final SignatureKeyPair keyPair = signatureKeyManager.getKeyPair();
        final Subject subject = EnvironmentContext.getCurrent().getSubject();
        final SubjectImpl subjectWithoutToken =
            new SubjectImpl(
                subject.getUserName(), subject.getUserId(), null, subject.isTemporary());
        token =
            Jwts.builder()
                .setPayload(GSON.toJson(subjectWithoutToken))
                .setHeader(
                    new HashMap<String, Object>() {
                      {
                        put("kind", MACHINE_TOKEN_KIND);
                      }
                    })
                .signWith(RS512, keyPair.getPrivate())
                .compact();
        tokens.put(workspaceId, userId, token);
      }
      return token;
    } finally {
      lock.writeLock().unlock();
    }
  }

  /**
   * Invalidates machine security tokens for all users of given workspace.
   *
   * @param workspaceId workspace to invalidate tokens
   * @return the copy of the tokens row, where row is a map where key is user id and value is token
   */
  public Map<String, String> removeTokens(String workspaceId) {
    lock.writeLock().lock();
    try {
      final Map<String, String> rowCopy = new HashMap<>(tokens.row(workspaceId));
      tokens.row(workspaceId).clear();
      return rowCopy;
    } finally {
      lock.writeLock().unlock();
    }
  }
}
