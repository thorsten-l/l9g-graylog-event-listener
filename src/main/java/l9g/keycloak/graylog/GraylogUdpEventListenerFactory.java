/*
 * Copyright 2025 Thorsten Ludewig (t.ludewig@gmail.com).
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * GraylogUdpEventListenerFactory
 *
 * This class implements the `EventListenerProviderFactory` interface from Keycloak
 * and is responsible for creating and configuring instances of the `GraylogUdpEventListener`.
 * It allows integration with Graylog for logging Keycloak events via UDP.
 */
package l9g.keycloak.graylog;

import org.keycloak.Config;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventListenerProviderFactory;
import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

public class GraylogUdpEventListenerFactory implements EventListenerProviderFactory {

  // Logger instance for logging messages
  private static final Logger logger = Logger.getLogger(GraylogUdpEventListenerFactory.class);

  // Default hostname for the GELF source
  private String hostname = "keycloak";

  // Default Graylog host and port for UDP communication
  private String gelfHost = "127.0.0.1";
  private int gelfPort = 12201;

  /**
   * Creates an instance of the `GraylogUdpEventListener`.
   *
   * @param session The Keycloak session.
   * @return An instance of `GraylogUdpEventListener`.
   * @throws RuntimeException if an error occurs during initialization.
   */
  @Override
  public EventListenerProvider create(KeycloakSession session) {
    try {
      return new GraylogUdpEventListener(session, hostname, gelfHost, gelfPort);
    } catch (Exception e) {
      logger.error("Error initializing GraylogUdpEventListener", e);
      throw new RuntimeException(e);
    }
  }

  /**
   * Initializes the factory with configuration values from Keycloak.
   *
   * @param config The configuration scope provided by Keycloak.
   */
  @Override
  public void init(Config.Scope config) {
    // Override default hostname if provided in the configuration
    if (config.get("hostname") != null) {
      hostname = config.get("hostname");
    }

    // Override default GELF host if provided in the configuration
    if (config.get("gelf-host") != null) {
      gelfHost = config.get("gelf-host");
    }

    // Override default GELF port if provided in the configuration
    if (config.get("gelf-port") != null) {
      gelfPort = config.getInt("gelf-port", 12201);
    }

    // Log the configured GELF source and address
    logger.infof("gelf source = %s", hostname);
    logger.infof("gelf address = %s:%d", gelfHost, gelfPort);
  }

  /**
   * Post-initialization hook. Currently unused.
   *
   * @param factory The Keycloak session factory.
   */
  @Override
  public void postInit(KeycloakSessionFactory factory) {
    // No post-initialization logic required
  }

  /**
   * Closes the factory. Currently unused.
   */
  @Override
  public void close() {
    // No cleanup logic required
  }

  /**
   * Returns the unique identifier for this factory.
   *
   * @return The factory ID.
   */
  @Override
  public String getId() {
    return "l9g-graylog";
  }
}
