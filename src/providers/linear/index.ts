import type { AuthServer } from "../../auth/server.js";
import {
  CONNECTION_ATTEMPT_LIFETIME_MINUTES,
  callbackConnectionAccess,
  connectionAccess,
  connectionActionFailure,
  connectionCallbackFailure,
  connectionResult,
  manageConnectionAccess,
  newConnectionState,
  readNonEmptyEnvironmentVariable,
  requiredConnectionId,
  stateHash,
} from "../../connections/shared.js";
import { DatabaseUnavailableError } from "../../db/errors.js";
import type { Database, LinearConnectionRecord } from "../../db/types.js";
import { outputContextProvider, replyOutputTool } from "../../execution-capabilities/outputs.js";
import { logger } from "../../logger.js";
import { createLinearTriggerProvider } from "../../triggers/linear/provider.js";
import { createLinearReplyExecutor } from "../../triggers/linear/reply.js";
import { createLinearWebhookSource } from "../../triggers/linear/webhook.js";
import type { ProviderConnectionRegistration, ProviderRegistration } from "../registration.js";
import {
  createLinearApiClient,
  createLinearConnectionClient,
  hasRequiredLinearScopes,
  type LinearApiClient,
  type LinearConnectionClient,
  type LinearInstallation,
} from "./client.js";

export interface LinearRegistrationConfiguration {
  clientId: string;
  clientSecret: string;
  webhookSecret: string;
}

export interface CreateLinearRegistrationOptions {
  database: Database | null;
  auth: AuthServer | null;
  applicationBaseUrl: string;
  publicBaseUrl?: string;
  environment?: NodeJS.ProcessEnv;
  configuration?: LinearRegistrationConfiguration | null;
  connectionClient?: LinearConnectionClient;
  apiClient?: LinearApiClient;
  fetch?: typeof fetch;
}

interface LinearConnectionOptions {
  database: Database;
  auth: AuthServer;
  applicationBaseUrl: string;
}

export function createLinearRegistration(
  options: CreateLinearRegistrationOptions,
): ProviderRegistration {
  const configuration =
    options.configuration === undefined
      ? readLinearConfiguration(options.publicBaseUrl, options.environment ?? process.env)
      : options.configuration;
  if (configuration === null || options.publicBaseUrl === undefined) {
    return emptyLinearRegistration(options);
  }
  const connectionClient =
    options.connectionClient ??
    createLinearConnectionClient({
      clientId: configuration.clientId,
      clientSecret: configuration.clientSecret,
      publicBaseUrl: options.publicBaseUrl,
      ...(options.fetch === undefined ? {} : { fetch: options.fetch }),
    });
  const database = options.database;
  const api =
    database === null
      ? undefined
      : (options.apiClient ??
        createLinearApiClient({
          connectionForLinearOrganization: (linearOrganizationId) =>
            database.findLinearConnection(linearOrganizationId),
          updateTokens: (input) => database.updateLinearConnectionTokens(input),
          connectionClient,
          ...(options.fetch === undefined ? {} : { fetch: options.fetch }),
        }));
  const accept =
    database === null
      ? () => Promise.reject(new DatabaseUnavailableError())
      : (input: Parameters<Database["acceptLinearEvent"]>[0]) => database.acceptLinearEvent(input);
  const webhook = createLinearWebhookSource({
    signingSecret: configuration.webhookSecret,
    accept,
    ...(api === undefined
      ? {}
      : {
          resolveIssue: ({ linearOrganizationId, issueId }) =>
            api.readIssue({ linearOrganizationId, issueId }),
        }),
  });
  if (database === null) {
    return {
      connection: linearConnectionStatus(true),
      triggerProviders: [],
      sources: [webhook],
      outputs: [],
      requests: [{ name: "linear.events", handle: (request) => webhook.handle(request) }],
    };
  }
  const connection =
    options.auth === null
      ? linearConnectionStatus(true)
      : createLinearConnection(
          { database, auth: options.auth, applicationBaseUrl: options.applicationBaseUrl },
          connectionClient,
        );
  return {
    connection,
    triggerProviders: [
      ({ configurationStoreForProject }) =>
        createLinearTriggerProvider({ configurationStoreForProject }),
    ],
    sources: [webhook],
    outputs:
      api === undefined
        ? []
        : [
            {
              type: "linear.reply",
              tool: replyOutputTool,
              available: outputContextProvider("linear"),
              execute: createLinearReplyExecutor({ client: api }),
            },
          ],
    requests: [{ name: "linear.events", handle: (request) => webhook.handle(request) }],
  };
}

function emptyLinearRegistration(
  options: Pick<CreateLinearRegistrationOptions, "database" | "auth" | "applicationBaseUrl">,
): ProviderRegistration {
  const connection =
    options.database === null || options.auth === null
      ? linearConnectionStatus(false)
      : createLinearConnection(
          {
            database: options.database,
            auth: options.auth,
            applicationBaseUrl: options.applicationBaseUrl,
          },
          undefined,
        );
  return { connection, triggerProviders: [], sources: [], outputs: [], requests: [] };
}

function linearConnectionStatus(configured: boolean): ProviderConnectionRegistration {
  return {
    name: "linear",
    status: (connections) => linearStatus(configured, connections.linear),
    actions: {},
  };
}

function createLinearConnection(
  options: LinearConnectionOptions,
  client: LinearConnectionClient | undefined,
): ProviderConnectionRegistration {
  const start = async (request: Request): Promise<Response> => {
    const rejected = options.auth.rejectCookieMutation(request);
    if (rejected !== undefined) return rejected;
    try {
      const access = await manageConnectionAccess(options.auth, options.database, request);
      if (client === undefined)
        return Response.json({ error: "provider_not_configured" }, { status: 409 });
      const state = newConnectionState();
      await options.database.startConnectionAttempt({
        provider: "linear",
        stateVerifier: stateHash(state),
        access: connectionAccess(access),
        lifetimeMinutes: CONNECTION_ATTEMPT_LIFETIME_MINUTES,
      });
      return Response.json({ url: client.authorizationUrl(state) });
    } catch (error) {
      return connectionActionFailure(error, "linear", "start");
    }
  };

  const disconnect = async (request: Request): Promise<Response> => {
    const rejected = options.auth.rejectCookieMutation(request);
    if (rejected !== undefined) return rejected;
    try {
      const access = await manageConnectionAccess(options.auth, options.database, request);
      const disconnected = await options.database.disconnectConnection(
        "linear",
        requiredConnectionId(request),
        connectionAccess(access),
      );
      if (disconnected.provider === "linear" && disconnected.accessToken !== undefined) {
        void client?.revoke(disconnected.accessToken).catch((error: unknown) => {
          logger.warn(
            { err: error, provider: "linear" },
            "provider cleanup failed after disconnect",
          );
        });
      }
      return Response.json({ disconnected: true });
    } catch (error) {
      return connectionActionFailure(error, "linear", "disconnect");
    }
  };

  return {
    name: "linear",
    status: (connections) => linearStatus(client !== undefined, connections.linear),
    actions: {
      start,
      disconnect,
      callback: (request) => completeAuthorization(options, client, request),
    },
  };
}

async function completeAuthorization(
  options: LinearConnectionOptions,
  client: LinearConnectionClient | undefined,
  request: Request,
): Promise<Response> {
  const url = new URL(request.url);
  const state = url.searchParams.get("state");
  const code = url.searchParams.get("code");
  if (state === null || code === null || client === undefined) {
    return connectionResult(options.applicationBaseUrl, "/", "connection_unavailable");
  }
  let returnRoute = "/";
  try {
    const access = await callbackConnectionAccess(options.auth, request);
    const attempt = await options.database.readConnectionAttempt({
      stateVerifier: stateHash(state),
      phase: "linear_authorization",
      access,
    });
    returnRoute = attempt.returnRoute;
    const installation = await client.exchangeCode(code);
    await bindLinear(options.database, state, access, installation);
    return connectionResult(options.applicationBaseUrl, attempt.returnRoute, "linear_connected");
  } catch (error) {
    return connectionCallbackFailure({
      error,
      provider: "linear",
      phase: "authorization",
      applicationBaseUrl: options.applicationBaseUrl,
      returnRoute,
    });
  }
}

async function bindLinear(
  database: Database,
  state: string,
  access: Awaited<ReturnType<typeof callbackConnectionAccess>>,
  installation: LinearInstallation,
): Promise<void> {
  await database.bindLinearConnection({
    stateVerifier: stateHash(state),
    phase: "linear_authorization",
    access,
    ...installation,
  });
}

function linearStatus(configured: boolean, bindings: readonly LinearConnectionRecord[]) {
  if (!configured) return { status: "notConfigured" as const };
  if (bindings.length === 0) return { status: "disconnected" as const };
  return bindings.some((binding) => !hasRequiredLinearScopes(binding.scopes))
    ? { status: "requiresReauthorization" as const }
    : { status: "connected" as const };
}

function readLinearConfiguration(
  publicBaseUrl: string | undefined,
  environment: NodeJS.ProcessEnv,
): LinearRegistrationConfiguration | null {
  if (publicBaseUrl === undefined) return null;
  const clientId = readNonEmptyEnvironmentVariable(environment, "LINEAR_CLIENT_ID");
  const clientSecret = readNonEmptyEnvironmentVariable(environment, "LINEAR_CLIENT_SECRET");
  const webhookSecret = readNonEmptyEnvironmentVariable(environment, "LINEAR_WEBHOOK_SECRET");
  return clientId === undefined || clientSecret === undefined || webhookSecret === undefined
    ? null
    : { clientId, clientSecret, webhookSecret };
}
